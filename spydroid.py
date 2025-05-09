import requests, os, time

API_KEY = "01959d7cad79805c5131e7a9f8f0cab51205a2c9655a375c8f93fadd70e69da5"
HEADERS = {"x-apikey": API_KEY}

def show_banner():
    banner = r"""
   _____             _ ____              _     
  / ____|           | |  _ \            | |    
 | (___   ___   ___ | | |_) | ___   ___ | |___ 
  \___ \ / _ \ / _ \| |  _ < / _ \ / _ \| / __|
  ____) | (_) | (_) | | |_) | (_) | (_) | \__ \
 |_____/ \___/ \___/|_|____/ \___/ \___/|_|___/
       🛡️ SpyDroid Scanner — by fsociety 🛡️
    """
    print(banner)

def choose_language():
    lang = input("اختر اللغة / Choose language [ar/en]: ").strip().lower()
    return "ar" if lang == "ar" else "en"

def get_input(lang):
    if lang == "ar":
        kind = input("هل تريد فحص ملف أم رابط؟ [ملف/رابط]: ").strip()
        if "رابط" in kind:
            return "url", input("أدخل الرابط: ").strip()
        return "file", input("أدخل مسار الملف: ").strip()
    else:
        kind = input("Scan file or URL? [file/url]: ").strip()
        if "url" in kind:
            return "url", input("Enter the URL: ").strip()
        return "file", input("Enter file path: ").strip()

def upload_file(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    with open(filepath, 'rb') as f:
        response = requests.post(url, headers=HEADERS, files={"file": f})
    return response.json()["data"]["id"]

def upload_url(scan_url):
    url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(url, headers=HEADERS, data={"url": scan_url})
    return response.json()["data"]["id"]

def get_result(scan_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    while True:
        r = requests.get(url, headers=HEADERS)
        data = r.json()
        if data["data"]["attributes"]["status"] == "completed":
            return data["data"]["attributes"]["stats"]
        time.sleep(2)

def interpret_result(stats, lang):
    level = stats["malicious"] + stats.get("suspicious", 0)
    print("\n" + ("[🔍] النتيجة:" if lang == "ar" else "[🔍] Result:"))
    if level <= 2:
        print("✅ آمن" if lang == "ar" else "✅ Safe")
    elif 3 <= level <= 5:
        print("⚠️ مشبوه" if lang == "ar" else "⚠️ Suspicious")
    elif 6 <= level <= 10:
        print("🚨 خطير" if lang == "ar" else "🚨 Dangerous")
    elif 11 <= level <= 15:
        print("☠️ خطير جدًا" if lang == "ar" else "☠️ Very Dangerous")
    else:
        print("🔥 تهديد عالي المستوى!" if lang == "ar" else "🔥 Critical Threat!")
    
    print((f"تم الكشف بواسطة: {level} محركًا" if lang == "ar" else f"Detected by: {level} engines"))

    # التوقيع
    print("\n" + "-"*45)
    print("🔖 النتيجة مقدمة من SpyDroid v1.0 - fsociety" if lang == "ar" else "🔖 Report by SpyDroid v1.0 - fsociety")
    print("-"*45)

def main():
    show_banner()
    lang = choose_language()
    kind, value = get_input(lang)
    try:
        if kind == "file":
            if not os.path.exists(value):
                print("الملف غير موجود" if lang == "ar" else "File not found")
                return
            scan_id = upload_file(value)
        else:
            scan_id = upload_url(value)
        stats = get_result(scan_id)
        interpret_result(stats, lang)
    except Exception as e:
        print("خطأ أثناء الفحص:" if lang == "ar" else "Error:", str(e))

main()
