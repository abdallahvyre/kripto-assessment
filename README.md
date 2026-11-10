# Kripto

Kripto أداة سطر أوامر معيارية لإجراء تقييمات أمنية مصرح بها لتطبيقات الويب. تجمع سطح الهجوم، تنفذ فحوصًا سلبية أو نشطة وفق النمط المختار، تربط الأدلة، وتنتج تقارير نصية وJSON مع دعم PDF اختياري.

> استخدم الأداة فقط على الأنظمة التي تملكها أو لديك تصريح صريح لاختبارها. الوضع الافتراضي `safe` منخفض الأثر، بينما يتطلب الوضعان `active` و`intrusive` الخيار `--ack-authorized`.

## المزايا الأساسية

- اكتشاف تقنيات الويب وWAF وTLS والمنافذ والمسارات وواجهات API.
- تحليل JavaScript وSPA والمصادقة والتحكم بالوصول وSQLi وXSS.
- تحديد النطاق، ضبط المعدل والميزانيات، ودعم الوكيل وTor دون رجوع صامت إلى اتصال مباشر.
- تخزين محلي اختياري في SQLite وتقارير TXT وJSON وPDF.
- إضافات Python موثوقة يتم تفعيلها صراحة من سطر الأوامر.

## المتطلبات

- Python 3.10 أو أحدث.
- اتصال شبكي بالهدف المصرح به.
- Windows أو Linux أو macOS. يتضمن المستودع حزمة Tor لويندوز، ويمكن تحديد حزمة أخرى عبر `--tor-root`.

## التثبيت

على PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

على Linux أو macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

لإنشاء تقارير PDF:

```powershell
python -m pip install ".[reports]"
```

للتصيير الاختياري عبر Chromium:

```powershell
python -m pip install ".[browser]"
python -m playwright install chromium
```

يمكن أيضًا تثبيت المشروع والحصول على الأمر `kripto`:

```powershell
python -m pip install .
kripto --help
```

## التشغيل

تشغيل الواجهة التفاعلية:

```powershell
python main.py
```

فحص آمن لهدف مصرح به:

```powershell
python main.py --url https://your-domain.example
```

فحص نشط بعد تأكيد التفويض:

```powershell
python main.py --url https://your-domain.example --mode active --ack-authorized
```

لعرض جميع الخيارات والملفات التعريفية:

```powershell
python main.py --help
python main.py --list-profiles
```

على Windows يمكن استخدام `krypto.bat`. عيّن `KRIPTO_NO_ELEVATE=1` إذا لم ترغب في طلب صلاحيات مرتفعة.

## الرابط المحلي والمنفذ

Kripto برنامج CLI ولا يشغّل تطبيق ويب محليًا، لذلك لا يوجد رابط أو منفذ خاص بواجهة الأداة. لفحص خدمة محلية مرّر رابطها كاملًا، ويمكن تغيير منفذ الهدف داخل الرابط:

```powershell
python main.py --url http://127.0.0.1:8000
python main.py --url https://127.0.0.1:8443
```

منفذ Tor الافتراضي هو `9050` ويمكن تغييره باستخدام `--tor-port`.

## نقاط API وcurl

المشروع لا يعرّض API خادمية. هو عميل تقييم يتصل بالهدف المحدد. يمكن التحقق يدويًا من استجابة هدف مصرح به قبل التشغيل:

```bash
curl -I https://your-domain.example
```

## المصادقة والمتغيرات البيئية

استخدم `--headers-file` لرؤوس طلب محلية، أو `--auth-file` لهويات متعددة، أو `--auth-from-env` لمتغيرات تبدأ بـ `KRIPTO_AUTH_`. يدعم ملف الهوية مراجع من الشكل `${ENV:NAME}` حتى لا تُكتب الأسرار داخل الملف.

المتغيرات المهمة:

| المتغير | الغرض |
| --- | --- |
| `KRIPTO_AUTH_<NAME>_<FIELD>` | تعريف هوية مصرح بها من البيئة |
| `KRIPTO_REPORT_FONT` | مسار خط Unicode لتقارير PDF |
| `KRIPTO_NO_UI` | تعطيل لوحة العرض التفاعلية |
| `KRIPTO_NO_SPLASH` | تعطيل شاشة البداية |
| `KRIPTO_NO_ELEVATE` | منع طلب الرفع في مشغل Windows |

## سياسة حفظ البيانات

- تُكتب التقارير وقاعدة SQLite افتراضيًا داخل `output/`، وهذا المجلد مستبعد من Git.
- تُحجب كلمات المرور والرموز والاعتمادات المكتشفة افتراضيًا.
- `--no-store` يمنع حفظ سجل SQLite.
- `--include-secrets` يحفظ القيم الكاملة؛ لا تستخدمه إلا مع مسار محمي ولا ترفع المخرجات إلى GitHub.
- ملفات الهوية والرؤوس وملفات `.env` مستبعدة من Git ويجب إبقاؤها محليًا.

## بنية المشروع

```text
core/       منطق الفحص والتقارير والواجهة
plugins/    إضافات اختيارية موثوقة
tor/        حزمة Tor المرفقة لويندوز
config.py   إعدادات وحدود التشغيل
main.py     نقطة الدخول الرئيسية
krypto.bat  مشغل Windows
```

لا يحتوي المشروع على تدريب نماذج أو أوزان تعلم آلي.

## English summary

Kripto is a modular command-line toolkit for authorized web application security assessments. Install the base dependencies with `pip install -r requirements.txt`, run `python main.py --help`, and use it only against systems you own or are explicitly authorized to test. Generated reports, databases, credentials, and environment files must remain outside version control.
