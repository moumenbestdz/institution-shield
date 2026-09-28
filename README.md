# 🛡️ Institution Shield | درع المؤسسات

نظام حماية مفتوح المصدر للمؤسسات الاقتصادية الصغيرة والمتوسطة، مكتوب بلغة Python.
Open-source defensive toolkit for small and mid-size financial institutions.

## المزايا | Features
- 🔐 تشفير AES-256-GCM للبيانات الحساسة | AES-256-GCM encryption at rest
- 🧾 سجل تدقيق مقاوم للتلاعب (HMAC متسلسل) | Tamper-evident hash-chained audit log
- 👤 مصادقة: scrypt + TOTP + قفل الحساب + صلاحيات حسب الدور | Auth: scrypt, TOTP MFA, lockout, RBAC
- 🚨 كشف الاحتيال بقواعد وإحصاء مع تنبيهات | Rule + statistical fraud detection with alerts
- 🌐 واجهة REST API (FastAPI) | REST API
- 💾 تخزين SQLite مشفّر | Encrypted SQLite storage

## التشغيل | Quick start
```bash
pip install -r requirements.txt
python institution_shield.py            # تجربة سريعة | quick demo
python shield_storage.py                # تجربة التخزين | storage demo
python api.py create-admin admin1       # إنشاء أول مدير | create first admin
python api.py                           # تشغيل الخادم | run server (127.0.0.1:8000)
```

## ⚠️ تنبيه مهم | Important disclaimer
- هذا المشروع **تعليمي/تجريبي** ولم يخضع لمراجعة أمنية مستقلة. لا تعتمد عليه وحده لحماية أموال أو بيانات حقيقية.
  This project has **not** had an independent security audit. Do not rely on it alone to protect real funds or data.
- شغّله خلف TLS (Nginx/Caddy) دائماً، واحفظ المفتاح `SHIELD_KEY` في KMS/HSM.
  Always run behind TLS and keep the master key (`SHIELD_KEY`) in a KMS/HSM.
- الجلسات في الذاكرة (عملية واحدة فقط). Sessions
