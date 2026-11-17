"""Bilingual (Arabic / English) security rules.

Each rule has:
  id, category (links to compliance.json), severity, languages (file extensions or
  special names), regex pattern, and bilingual title / description / fix.
"""
import re

CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".rb", ".cs", ".kt"}
CONFIG_EXT = {".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".properties", ".toml", ".xml", ".tf"}
ALL_TEXT = CODE_EXT | CONFIG_EXT | {".sh", ".txt", ".pem", ".key"}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

RULES = [
    # ---------------- Secrets ----------------
    {
        "id": "SEC001", "category": "secrets", "severity": "critical", "ext": ALL_TEXT,
        "pattern": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "title": {"en": "AWS access key committed to source", "ar": "مفتاح وصول AWS مكشوف في الكود"},
        "desc": {"en": "An AWS access key ID was found. Anyone with repo access can use it to reach your cloud account.",
                 "ar": "تم العثور على مفتاح وصول AWS. أي شخص يملك صلاحية قراءة المستودع يستطيع استخدامه للوصول إلى حسابك السحابي."},
        "fix": {"en": "Revoke the key in AWS IAM immediately, move it to a secrets manager (AWS Secrets Manager / Vault) and read it from an environment variable.",
                "ar": "ألغِ المفتاح فوراً من AWS IAM، وانقله إلى مدير أسرار (AWS Secrets Manager أو Vault)، واقرأه من متغير بيئة."},
    },
    {
        "id": "SEC002", "category": "secrets", "severity": "critical", "ext": ALL_TEXT,
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "title": {"en": "Private key committed to source", "ar": "مفتاح خاص (Private Key) مخزّن في المستودع"},
        "desc": {"en": "A private cryptographic key is stored in the repository.",
                 "ar": "مفتاح تشفير خاص محفوظ داخل المستودع، مما يسمح بانتحال الهوية أو فك التشفير."},
        "fix": {"en": "Rotate the key pair, remove it from git history (git filter-repo) and store it in a vault or HSM.",
                "ar": "بدّل زوج المفاتيح، واحذفه من تاريخ git (git filter-repo)، وخزّنه في Vault أو HSM."},
    },
    {
        "id": "SEC003", "category": "secrets", "severity": "high", "ext": ALL_TEXT,
        "pattern": r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]",
        "title": {"en": "Hardcoded API key / token", "ar": "مفتاح API أو رمز وصول مكتوب مباشرة في الكود"},
        "desc": {"en": "A credential-like value is hardcoded in the source.",
                 "ar": "قيمة تشبه بيانات اعتماد مكتوبة بشكل ثابت داخل الكود المصدري."},
        "fix": {"en": "Load secrets from environment variables or a secrets manager; rotate the exposed value.",
                "ar": "حمّل الأسرار من متغيرات البيئة أو مدير أسرار، واستبدل القيمة المكشوفة."},
    },
    {
        "id": "SEC004", "category": "secrets", "severity": "high", "ext": ALL_TEXT,
        "pattern": r"(?i)\b(password|passwd|pwd|db_pass(word)?)\b\s*[:=]\s*['\"][^'\"\s]{4,}['\"]",
        "title": {"en": "Hardcoded password", "ar": "كلمة مرور مكتوبة مباشرة في الكود"},
        "desc": {"en": "A password appears to be hardcoded.",
                 "ar": "يبدو أن كلمة مرور مكتوبة بشكل ثابت في الكود."},
        "fix": {"en": "Use environment variables / a vault and rotate the password.",
                "ar": "استخدم متغيرات البيئة أو Vault، وغيّر كلمة المرور."},
    },
    {
        "id": "SEC005", "category": "secrets", "severity": "critical", "ext": ALL_TEXT,
        "pattern": r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,})\b",
        "title": {"en": "Platform token (GitHub / Slack / Stripe live)", "ar": "رمز منصة مكشوف (GitHub أو Slack أو Stripe)"},
        "desc": {"en": "A live platform token was found.", "ar": "تم العثور على رمز وصول فعّال لمنصة خارجية."},
        "fix": {"en": "Revoke the token in the provider console and use CI secrets.",
                "ar": "ألغِ الرمز من لوحة المزوّد، واستخدم أسرار CI بدلاً منه."},
    },
    # ---------------- Injection ----------------
    {
        "id": "INJ001", "category": "injection", "severity": "high", "ext": CODE_EXT,
        "pattern": r"(?i)\.(execute|query|raw)\s*\(\s*(f['\"]|['\"][^'\"]*(select|insert|update|delete)[^'\"]*['\"]\s*(\+|%|\.format))",
        "title": {"en": "SQL query built from string concatenation", "ar": "استعلام SQL مبني بدمج النصوص (خطر حقن SQL)"},
        "desc": {"en": "User input concatenated into SQL can lead to SQL injection.",
                 "ar": "دمج مدخلات المستخدم داخل استعلام SQL قد يؤدي إلى هجوم حقن SQL وتسريب قاعدة البيانات."},
        "fix": {"en": "Use parameterised queries, e.g. cursor.execute(\"... WHERE id = %s\", (user_id,)).",
                "ar": "استخدم الاستعلامات المُعلَّمة (Parameterized)، مثل: cursor.execute(\"... WHERE id = %s\", (user_id,))."},
    },
    {
        "id": "INJ002", "category": "injection", "severity": "high", "ext": CODE_EXT,
        "pattern": r"(?<![\w.])(eval|exec)\s*\(",
        "title": {"en": "Dynamic code execution (eval/exec)", "ar": "تنفيذ كود ديناميكي (eval/exec)"},
        "desc": {"en": "eval/exec on untrusted input allows remote code execution.",
                 "ar": "استخدام eval أو exec على مدخلات غير موثوقة يسمح بتنفيذ أوامر عن بُعد."},
        "fix": {"en": "Remove eval/exec; use safe parsers (json.loads, ast.literal_eval) or explicit dispatch tables.",
                "ar": "احذف eval/exec، واستخدم محللات آمنة (json.loads أو ast.literal_eval) أو جداول توجيه صريحة."},
    },
    {
        "id": "INJ003", "category": "injection", "severity": "high", "ext": CODE_EXT,
        "pattern": r"(shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec)",
        "title": {"en": "OS command execution via shell", "ar": "تنفيذ أوامر نظام التشغيل عبر Shell"},
        "desc": {"en": "Passing input to a shell enables command injection.",
                 "ar": "تمرير المدخلات إلى Shell يفتح الباب لهجوم حقن الأوامر."},
        "fix": {"en": "Use argument lists without a shell (subprocess.run([...], shell=False)) and validate input.",
                "ar": "مرّر الأوامر كقائمة دون Shell (subprocess.run([...], shell=False)) وتحقّق من المدخلات."},
    },
    # ---------------- Crypto / TLS ----------------
    {
        "id": "CRY001", "category": "crypto", "severity": "medium", "ext": CODE_EXT,
        "pattern": r"(?i)(hashlib\.(md5|sha1)\s*\(|createHash\s*\(\s*['\"](md5|sha1)['\"]|MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1)\")",
        "title": {"en": "Weak hashing algorithm (MD5/SHA-1)", "ar": "خوارزمية تجزئة ضعيفة (MD5 أو SHA-1)"},
        "desc": {"en": "MD5 and SHA-1 are broken for security purposes.",
                 "ar": "خوارزميتا MD5 وSHA-1 مكسورتان ولا تصلحان للاستخدامات الأمنية."},
        "fix": {"en": "Use SHA-256+ for integrity, and bcrypt/argon2 for passwords.",
                "ar": "استخدم SHA-256 أو أعلى للتحقق من السلامة، وbcrypt أو argon2 لكلمات المرور."},
    },
    {
        "id": "TLS001", "category": "tls", "severity": "high", "ext": CODE_EXT,
        "pattern": r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
        "title": {"en": "TLS certificate verification disabled", "ar": "تعطيل التحقق من شهادة TLS"},
        "desc": {"en": "Disabling certificate checks allows man-in-the-middle attacks.",
                 "ar": "تعطيل التحقق من الشهادات يسمح بهجمات الوسيط (MITM) واعتراض البيانات."},
        "fix": {"en": "Keep verification on; trust internal CAs via a CA bundle instead.",
                "ar": "أبقِ التحقق مفعّلاً، وأضف شهادة الجهة الداخلية (CA bundle) عند الحاجة."},
    },
    # ---------------- Insecure config ----------------
    {
        "id": "CFG001", "category": "config", "severity": "medium", "ext": CODE_EXT | CONFIG_EXT,
        "pattern": r"(?i)\b(debug\s*[:=]\s*true|app\.run\([^)]*debug\s*=\s*True)",
        "title": {"en": "Debug mode enabled", "ar": "وضع التصحيح (Debug) مفعّل"},
        "desc": {"en": "Debug mode can leak stack traces and enable interactive consoles in production.",
                 "ar": "وضع التصحيح قد يكشف تفاصيل الأخطاء الداخلية ويفتح واجهات تحكم في بيئة الإنتاج."},
        "fix": {"en": "Drive debug from an environment variable and default it to false.",
                "ar": "اجعل وضع التصحيح يُضبط من متغير بيئة، وقيمته الافتراضية false."},
    },
    {
        "id": "CFG002", "category": "config", "severity": "medium", "ext": CODE_EXT | CONFIG_EXT,
        "pattern": r"(Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|origins?\s*[:=]\s*['\"]\*['\"]|CORS\([^)]*origins\s*=\s*['\"]\*)",
        "title": {"en": "CORS allows any origin (*)", "ar": "سياسة CORS تسمح لأي نطاق (*)"},
        "desc": {"en": "Wildcard CORS lets any website call your API from a user's browser.",
                 "ar": "السماح لكل النطاقات يمكّن أي موقع من استدعاء واجهتك البرمجية من متصفح المستخدم."},
        "fix": {"en": "Allow-list the specific trusted origins.", "ar": "حدّد قائمة صريحة بالنطاقات الموثوقة فقط."},
    },
    # ---------------- Deserialization / XSS ----------------
    {
        "id": "DES001", "category": "deserialization", "severity": "high", "ext": CODE_EXT,
        "pattern": r"(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|ObjectInputStream\s*\(|unserialize\s*\()",
        "title": {"en": "Unsafe deserialization", "ar": "فك تسلسل غير آمن (Deserialization)"},
        "desc": {"en": "Deserializing untrusted data can execute arbitrary code.",
                 "ar": "فك تسلسل بيانات غير موثوقة قد يؤدي إلى تنفيذ كود عشوائي على الخادم."},
        "fix": {"en": "Use JSON or yaml.safe_load; never unpickle untrusted data.",
                "ar": "استخدم JSON أو yaml.safe_load، ولا تفك تسلسل pickle من مصدر غير موثوق."},
    },
    {
        "id": "XSS001", "category": "xss", "severity": "medium", "ext": {".js", ".ts", ".jsx", ".tsx", ".html"},
        "pattern": r"(\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()",
        "title": {"en": "Possible DOM XSS sink", "ar": "احتمال ثغرة XSS في واجهة المتصفح"},
        "desc": {"en": "Writing untrusted data as HTML enables cross-site scripting.",
                 "ar": "إدراج بيانات غير موثوقة كـ HTML يسمح بحقن سكربتات خبيثة (XSS)."},
        "fix": {"en": "Use textContent or sanitize with DOMPurify.", "ar": "استخدم textContent أو نظّف المحتوى بمكتبة DOMPurify."},
    },
]

# File-level rules (checked with custom logic in scanners.py)
FILE_RULES = {
    "CON001": {
        "id": "CON001", "category": "container", "severity": "medium",
        "title": {"en": "Container runs as root", "ar": "الحاوية (Container) تعمل بصلاحيات root"},
        "desc": {"en": "Dockerfile has no non-root USER instruction.",
                 "ar": "ملف Dockerfile لا يحدد مستخدماً بصلاحيات محدودة (USER)."},
        "fix": {"en": "Add a dedicated user: RUN adduser -D app && USER app",
                "ar": "أضف مستخدماً مخصصاً: RUN adduser -D app ثم USER app"},
    },
    "CON002": {
        "id": "CON002", "category": "container", "severity": "low",
        "title": {"en": "Base image uses :latest or no tag", "ar": "الصورة الأساسية بدون إصدار محدد (latest)"},
        "desc": {"en": "Unpinned base images make builds non-reproducible and can pull vulnerable versions.",
                 "ar": "عدم تثبيت إصدار الصورة يجعل البناء غير قابل للتكرار وقد يجلب إصداراً مصاباً."},
        "fix": {"en": "Pin to a version or digest, e.g. python:3.12-slim@sha256:...",
                "ar": "ثبّت الإصدار أو البصمة، مثل python:3.12-slim@sha256:..."},
    },
    "DEP001": {
        "id": "DEP001", "category": "supply_chain", "severity": "low",
        "title": {"en": "Unpinned dependency", "ar": "اعتمادية برمجية بدون إصدار مثبّت"},
        "desc": {"en": "Dependencies without exact versions weaken supply-chain control and SBOM accuracy.",
                 "ar": "الاعتماديات بدون إصدار دقيق تُضعف التحكم في سلسلة التوريد ودقة قائمة المكونات (SBOM)."},
        "fix": {"en": "Pin exact versions and use a lock file (requirements.txt with ==, package-lock.json).",
                "ar": "ثبّت الإصدارات بدقة واستخدم ملف قفل (== في requirements.txt أو package-lock.json)."},
    },
}

for r in RULES:
    r["regex"] = re.compile(r["pattern"])
