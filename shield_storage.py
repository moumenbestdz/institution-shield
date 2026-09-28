#!/usr/bin/env python3
"""
shield_storage.py - persistent encrypted storage for Institution Shield.

Adds on top of institution_shield.py:
  * SQLite database with parameterized queries only (no SQL injection)
  * TOTP secrets and transaction payloads encrypted with AES-256-GCM before hitting disk
  * Users, lockout state and fraud baselines survive restarts
  * `python shield_storage.py verify` to check audit-log integrity from the command line

Put it in the same folder as institution_shield.py.
"""
import json
import os
import sqlite3
import sys
import threading

from institution_shield import (AuthManager, Shield, TransactionMonitor, totp)


class SecureDB:
    def __init__(self, path: str, vault):
        self.vault, self.lock = vault, threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        with self.lock:
            self.db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users(
                    username TEXT PRIMARY KEY, salt BLOB NOT NULL, hash BLOB NOT NULL,
                    totp_enc TEXT NOT NULL, role TEXT NOT NULL,
                    fails INTEGER NOT NULL, locked_until REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS transactions(
                    id TEXT PRIMARY KEY, account TEXT NOT NULL, ts REAL NOT NULL,
                    score INTEGER NOT NULL, action TEXT NOT NULL, payload_enc TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(account);
            """)

    # ---- users ----
    def save_user(self, username: str, u: dict):
        enc = self.vault.encrypt(u["totp"], context=f"user:{username}")
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,?,?)",
                (username, u["salt"], u["hash"], enc, u["role"], u["fails"], u["locked_until"]))
            self.db.commit()

    def load_users(self) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT * FROM users").fetchall()
        return {r[0]: {"salt": r[1], "hash": r[2],
                       "totp": self.vault.decrypt(r[3], context=f"user:{r[0]}"),
                       "role": r[4], "fails": r[5], "locked_until": r[6]} for r in rows}

    # ---- transactions ----
    def save_tx(self, tx: dict, result: dict):
        enc = self.vault.encrypt(json.dumps(tx), context=f"tx:{tx['id']}")
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO transactions VALUES (?,?,?,?,?,?)",
                            (str(tx["id"]), tx["account"], tx.get("ts", 0),
                             result["score"], result["action"], enc))
            self.db.commit()

    def load_transactions(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT id, payload_enc FROM transactions ORDER BY ts").fetchall()
        return [json.loads(self.vault.decrypt(enc, context=f"tx:{i}")) for i, enc in rows]


class PersistentAuth(AuthManager):
    def __init__(self, audit, alerts, db: SecureDB):
        super().__init__(audit, alerts)
        self.db = db
        self.users = db.load_users()

    def register(self, username, password, role):
        secret = super().register(username, password, role)
        self.db.save_user(username, self.users[username])
        return secret

    def login(self, username, password, otp, ip="?"):
        token = super().login(username, password, otp, ip)
        if username in self.users:          # persist fails / lockout state
            self.db.save_user(username, self.users[username])
        return token


class PersistentMonitor(TransactionMonitor):
    def __init__(self, alerts, vault, audit, db: SecureDB, **kw):
        super().__init__(alerts, vault, audit, **kw)
        self.db = db
        for tx in db.load_transactions():   # rebuild fraud baselines after restart
            self.history[tx["account"]].append(float(tx["amount"]))
            if tx.get("dest"):
                self.known_dest[tx["account"]].add(tx["dest"])

    def evaluate(self, tx):
        result = super().evaluate(tx)
        self.db.save_tx(tx, result)
        return result


class PersistentShield(Shield):
    def __init__(self, db_path="shield.db", log_path="audit.log", alert_handlers=None):
        super().__init__(log_path, alert_handlers)
        self.db = SecureDB(db_path, self.vault)
        self.auth = PersistentAuth(self.audit, self.alerts, self.db)
        self.monitor = PersistentMonitor(self.alerts, self.vault, self.audit, self.db)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        ok, line = PersistentShield().audit.verify()
        print("audit log intact ✅" if ok else f"TAMPERING DETECTED at line {line} ❌")
        sys.exit(0 if ok else 1)

    import tempfile
    os.chdir(tempfile.mkdtemp())

    s1 = PersistentShield()
    secret = s1.auth.register("admin1", "Str0ng-Passphrase!", "admin")
    raw = s1.db.db.execute("SELECT totp_enc FROM users").fetchone()[0]
    print("secret stored in plaintext on disk?", secret in raw)

    s2 = PersistentShield()                      # simulated restart
    print("login after restart:", bool(s2.auth.login("admin1", "Str0ng-Passphrase!", totp(secret))))

    for i in range(12):
        s2.monitor.evaluate({"id": f"t{i}", "account": "ACC1",
                             "amount": 1000 + i * 50, "dest": "SUP-1"})

    s3 = PersistentShield()                      # another restart: baseline is restored
    print(s3.monitor.evaluate({"id": "t99", "account": "ACC1", "amount": 60_000, "dest": "SUP-1"}))
    print("log intact:", s3.audit.verify())
