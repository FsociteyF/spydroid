# 🕷️ SpyDroid

### أداة SpyDroid — لفحص وتحليل الملفات والروابط (EXE/APK/URL) بأسلوب ذكي وسهل، تعطيك درجة الخطورة ومعلومات تحليلية بلغة عربية أو إنجليزية.

- لا يتطلب أوامر - فقط شغّله.
- يدعم Termux وLinux.
- كشف ذكي لعناوين URL أو أنواع الملفات.
- واجهة ثنائية اللغة (العربية/الإنجليزية).
- مستويات مخاطر بسيطة: آمن - مريب - خطير - حرج.

---

## 🧠 What is SpyDroid?

**SpyDroid** is an intelligent file & link analysis tool (supports EXE/APK/URL). It provides risk level and malware info in Arabic or English.

- No commands required – just run it
- Supports Termux & Linux
- Smart detection of URLs or file types
- Dual-language interface (Arabic / English)
- Simple risk levels: Safe – Suspicious – Dangerous – Critical

---

## 📸 صور الأداة | Tool Images

### 🧪 صورة أوامر الأداة | Commands Screenshot  
![SpyDroid Commands](https://github.com/FsociteyF/spydroid/blob/main/cmd.jpg?raw=true)

---

### 🛠️ واجهة الأدوات | Tools Interface  
![SpyDroid Tools](https://github.com/FsociteyF/spydroid/blob/main/tools.png?raw=true)

---

## 🚀 التثبيت والتشغيل | Installation & Running

```bash
# 1. تثبيت Python (إذا لم يكن مثبتًا)
pkg install python -y       # لتيرمكس
sudo apt install python3 -y # للينكس

# 2. تثبيت Git (إذا لم يكن مثبتًا)
pkg install git -y
# أو
sudo apt install git -y

# 3. تحميل الأداة
git clone https://github.com/FsociteyF/spydroid
cd spydroid

# 4. تثبيت المتطلبات
pip install requests colorama

# 5. تشغيل الأداة
python spydroid.py
