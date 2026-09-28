#!/usr/bin/env python3
"""
Institution Shield - integrated defensive protection for economic institutions.

Layers:
  1. Vault          : AES-256-GCM encryption of sensitive data at rest
  2. AuditLog       : tamper-evident, HMAC-chained log (any edit/deletion is detected)
  3. AuthManager    : scrypt password hashing, TOTP MFA, lockout, sessions, RBAC
  4. TransactionMonitor : rule + statistical fraud detection with risk scoring
  5. AlertManager   : severity-based alerts to console / webhook (Slack, Telegram bridge...)

Install:  pip install cryptography
Run demo: python institution_shield.py
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import statistics
import threading
import time
import urllib.request
from collections import defaultdict, deque
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ───────────────────────── 1. Encryption ─────────────────────────
class Vault:
    """AES-256-GCM. `context` binds a ciphertext to its record (anti-swap)."""

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._aes = AESGCM(master_key)

    @staticmethod
    def load_or_create_key(path: str = "shield.key") -> bytes:
        env = os.environ.get("SHIELD_KEY")  # preferred: inject from a KMS/HSM/secret manager
        if env:
            return base64.b64decode(env)
        p = Path(path)
        if p.exists():
            return base64.b64decode(p.read_bytes())
        key = AESGCM.generate_key(256)
        p.write_bytes(base64.b64encode(key))
        os.chmod(p, 0o600)
        return key

    def encrypt(self, plaintext: str, context: str = "") -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode(), context.encode())
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, token: str, context: str = "") -> str:
        raw = base64.b64decode(token)
        return self._aes.decrypt(raw[:12], raw[12:], context.encode()).decode()


def derive_key(master: bytes, purpose: str) -> bytes:
    return hmac.new(master, purpose.encode(), hashlib.sha256).digest()


# ───────────────────────── 2. Tamper-evident audit log ─────────────────────────
class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str, key: bytes):
        self.path, self.key, self.lock = Path(path), key, threading.Lock()
        self.last = self._tail()

    def _sign(self, body: dict) -> str:
        data = json.dumps(body, sort_keys=True).encode()
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def _tail(self) -> str:
        if not self.path.exists():
            return self.GENESIS
        last = None
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else self.GENESIS

    def write(self, event: str, actor: str, details: dict | None = None):
        with self.lock:
            body = {"ts": time.time(), "event": event, "actor": actor,
                    "details": details or {}, "prev": self.last}
            body["hash"] = self._sign(body)
            with self.path.open("a") as f:
                f.write(json.dumps(body, sort_keys=True) + "\n")
            self.last = body["hash"]

    def verify(self):
        """Returns (True, None) if intact, else (False, line_number_of_first_break)."""
        prev = self.GENESIS
        if not self.path.exists():
            return True, None
        with self.path.open() as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                h = rec.pop("hash")
                if rec["prev"] != prev or not hmac.compare_digest(h, self._sign(rec)):
                    return False, n
                prev = h
        return True, None


# ───────────────────────── 5. Alerts ─────────────────────────
class AlertManager:
    def __init__(self, audit: AuditLog, handlers=None):
        self.audit = audit
        self.handlers = handlers or [console_handler]

    def raise_alert(self, severity: str, rule: str, message: str, **ctx):
        alert = {"severity": severity, "rule": rule, "message": message, "ctx": ctx}
        self.audit.write("ALERT", "system", alert)
        for h in self.handlers:
            try:
                h(alert)
            except Exception as e:  # an alert channel must never crash the system
                self.audit.write("ALERT_HANDLER_ERROR", "system", {"error": str(e)})


def console_handler(alert: dict):
    icon = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}.get(alert["severity"], "•")
    print(f"{icon} [{alert['severity'].upper()}] {alert['rule']}: {alert['message']}")


def webhook_handler(url: str):
    def send(alert: dict):
        req = urllib.request.Request(url, json.dumps(alert).encode(),
                                     {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    return send  # ───────────────────────── 3. Authentication, MFA, RBAC ─────────────────────────
ROLES = {
    "admin": {"read", "write", "approve", "manage_users"},
    "accountant": {"read", "write"},
    "auditor": {"read", "verify_log"},
}


def totp(secret_b32: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32)
    counter = int((at or time.time()) // step)
    h = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (int.from_bytes(h[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


class AuthManager:
    MAX_FAILS, LOCK_SECONDS, SESSION_SECONDS = 5, 900, 900

    def __init__(self, audit: AuditLog, alerts: AlertManager):
        self.audit, self.alerts = audit, alerts
        self.users: dict[str, dict] = {}     # production: use an encrypted database
        self.sessions: dict[str, dict] = {}

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1,
                              dklen=32, maxmem=64 * 1024 * 1024)

    def register(self, username: str, password: str, role: str) -> str:
        if role not in ROLES:
            raise ValueError("unknown role")
        if len(password) < 12:
            raise ValueError("password must be at least 12 characters")
        salt = os.urandom(16)
        secret = base64.b32encode(os.urandom(20)).decode()
        self.users[username] = {"salt": salt, "hash": self._hash(password, salt),
                                "totp": secret, "role": role, "fails": 0, "locked_until": 0}
        self.audit.write("USER_CREATED", username, {"role": role})
        return secret  # show once to the user (QR code in authenticator app)

    def login(self, username: str, password: str, otp: str, ip: str = "?"):
        u, now = self.users.get(username), time.time()
        digest = self._hash(password, u["salt"] if u else b"\0" * 16)  # constant work
        if u and u["locked_until"] > now:
            self.audit.write("LOGIN_BLOCKED_LOCKED", username, {"ip": ip})
            return None
        ok = (u is not None
              and hmac.compare_digest(digest, u["hash"])
              and hmac.compare_digest(totp(u["totp"]), otp))
        if not ok:
            self.audit.write("LOGIN_FAIL", username, {"ip": ip})
            if u:
                u["fails"] += 1
                if u["fails"] >= self.MAX_FAILS:
                    u["locked_until"], u["fails"] = now + self.LOCK_SECONDS, 0
                    self.alerts.raise_alert("high", "brute_force",
                                            f"Account '{username}' locked after repeated failures", ip=ip)
            return None
        u["fails"] = 0
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {"user": username, "role": u["role"], "exp": now + self.SESSION_SECONDS}
        self.audit.write("LOGIN_OK", username, {"ip": ip})
        return token

    def authorize(self, token: str, permission: str) -> str:
        s = self.sessions.get(token)
        if not s or s["exp"] < time.time():
            self.sessions.pop(token, None)
            raise PermissionError("invalid or expired session")
        if permission not in ROLES[s["role"]]:
            self.audit.write("ACCESS_DENIED", s["user"], {"permission": permission})
            self.alerts.raise_alert("medium", "privilege_violation",
                                    f"{s['user']} tried '{permission}' without rights")
            raise PermissionError("insufficient privileges")
        return s["user"]


# ───────────────────────── 4. Fraud / anomaly detection ─────────────────────────
class TransactionMonitor:
    def __init__(self, alerts: AlertManager, vault: Vault, audit: AuditLog,
                 large_limit=100_000, velocity_max=5, velocity_window=60):
        self.alerts, self.vault, self.audit = alerts, vault, audit
        self.large_limit, self.velocity_max, self.velocity_window = large_limit, velocity_max, velocity_window
        self.history = defaultdict(list)             # account -> [amounts]
        self.recent = defaultdict(deque)             # account -> timestamps
        self.known_dest = defaultdict(set)           # account -> destinations seen
        self.near_limit = defaultdict(deque)         # account -> timestamps of just-under-limit tx

    def evaluate(self, tx: dict) -> dict:
        acc, amt = tx["account"], float(tx["amount"])
        ts = tx.get("ts", time.time())
        score, reasons = 0, []

        if amt >= self.large_limit:
            score += 50; reasons.append("amount above institutional limit")

        q = self.recent[acc]
        q.append(ts)
        while q and ts - q[0] > self.velocity_window:
            q.popleft()
        if len(q) > self.velocity_max:
            score += 35; reasons.append(f"velocity: {len(q)} tx in {self.velocity_window}s")

        if 0.9 * self.large_limit <= amt < self.large_limit:      # structuring / smurfing
            nl = self.near_limit[acc]
            nl.append(ts)
            while nl and ts - nl[0] > 86_400:
                nl.popleft()
            if len(nl) >= 3:
                score += 40; reasons.append("possible structuring (repeated just-under-limit)")

        hist = self.history[acc]
        if len(hist) >= 10:
            mean, sd = statistics.mean(hist), statistics.pstdev(hist) or 1
            z = (amt - mean) / sd
            if z > 3:
                score += 30; reasons.append(f"statistical outlier (z={z:.1f})")

        hour = time.localtime(ts).tm_hour
        if hour < 5 and amt > self.large_limit * 0.2:
            score += 15; reasons.append("large transfer at off-hours")

        dest = tx.get("dest")
        if dest and dest not in self.known_dest[acc] and amt > self.large_limit * 0.3:
            score += 20; reasons.append("large transfer to new beneficiary")

        hist.append(amt)
        if dest:
            self.known_dest[acc].add(dest)

        action = "block" if score >= 70 else "review" if score >= 40 else "allow"
        # sensitive payload stored encrypted, bound to the tx id
        blob = self.vault.encrypt(json.dumps(tx), context=str(tx["id"]))
        self.audit.write("TX_EVALUATED", acc, {"id": tx["id"], "score": score,
                                               "action": action, "enc": blob})
        if action != "allow":
            self.alerts.raise_alert("critical" if action == "block" else "high", "fraud_detection",
                                    f"tx {tx['id']} -> {action.upper()} (score {score}): " + "; ".join(reasons),
                                    account=acc)
        return {"score": score, "action": action, "reasons": reasons}


# ───────────────────────── Assembly + demo ─────────────────────────
class Shield:
    def __init__(self, log_path="audit.log", alert_handlers=None):
        master = Vault.load_or_create_key()
        self.vault = Vault(derive_key(master, "vault"))
        self.audit = AuditLog(log_path, derive_key(master, "audit"))
        self.alerts = AlertManager(self.audit, alert_handlers)
        self.auth = AuthManager(self.audit, self.alerts)
        self.monitor = TransactionMonitor(self.alerts, self.vault, self.audit)


if __name__ == "__main__":
    import tempfile
    os.chdir(tempfile.mkdtemp())
    s = Shield()

    secret = s.auth.register("admin1", "Str0ng-Passphrase!", "admin")
    token = s.auth.login("admin1", "Str0ng-Passphrase!", totp(secret), ip="10.0.0.5")
    print("login ok:", bool(token))

    for _ in range(5):                         # brute-force attempt
        s.auth.login("admin1", "wrong-password", "000000", ip="203.0.113.9")

    s.auth.authorize(token, "approve")
    for i in range(12):                        # normal traffic builds a baseline
        s.monitor.evaluate({"id": f"t{i}", "account": "ACC1", "amount": 1000 + i * 50, "dest": "SUP-1"})
    print(s.monitor.evaluate({"id": "t99", "account": "ACC1", "amount": 250_000, "dest": "NEW-77"}))

    print("log intact:", s.audit.verify())
    lines = Path("audit.log").read_text().splitlines()
    lines[3] = lines[3].replace("LOGIN", "XXXXX")           # simulate tampering
    Path("audit.log").write_text("\n".join(lines) + "\n")
    print("after tampering:", s.audit.verify())
