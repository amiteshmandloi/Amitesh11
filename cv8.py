import telebot
from telebot import types
import requests
import json
import time
import threading
import os
import random
import uuid
import socket
from urllib.parse import urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= CONFIGURATION =================
# ⚠️ YOUR TOKEN
BOT_TOKEN = '8502034302:AAHfXlgmycl2HN2BJ5WNw8v1KCijGZCkSAE'

# ⚠️ ADMIN ID
ADMIN_ID = 1351526830

# ⚠️ SPEED SETTING
MAX_WORKERS = 5

# API Constants
AD_ID = '968777a5-36e1-42a8-9aad-3dc36c3f77b2'
URL_MICROCART = "https://www.sheinindia.in/api/cart/microcart"
URL_CREATE = "https://www.sheinindia.in/api/cart/create"

# ================= GLOBAL STATE =================
bot = telebot.TeleBot(BOT_TOKEN)
user_states = {}
protection_config = {"active": False, "interval": 30, "mode": "REDEM"} 
live_monitor = {"active": False, "msg_id": None, "chat_id": None, "stats": {}}
file_lock = threading.Lock()
print_lock = threading.Lock()

# Files
FILES = {
    "SVI": "500.txt", "SVC": "1k.txt", "SVD": "2k.txt", "SVH": "4k.txt",
    "REDEM": "redem.txt", "USED": "used.txt", "INV": "invalid.txt",
    "COOKIES_1": "cookies.json", "COOKIES_2": "cookies1.json",
    "USERS": "allowed_users.json", "STATE": "state.json"
}

# ================= PERMISSIONS & UTILS =================
def load_allowed_users():
    if not os.path.exists(FILES["USERS"]): return {}
    try:
        with open(FILES["USERS"], 'r') as f: return json.load(f)
    except: return {}

def is_authorized(chat_id):
    if str(chat_id) == str(ADMIN_ID): return True
    users = load_allowed_users()
    return str(chat_id) in users

def load_system_state():
    global protection_config
    if os.path.exists(FILES["STATE"]):
        try:
            with open(FILES["STATE"], "r") as f: 
                data = json.load(f)
                protection_config.update(data)
        except: pass

def save_system_state():
    try:
        with open(FILES["STATE"], "w") as f: json.dump(protection_config, f)
    except: pass

def print_console(trigger_user, code, status, msg=""):
    timestamp = time.strftime('%H:%M:%S')
    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    
    user_tag = f"USER:{str(trigger_user)[-4:]}"
    with print_lock:
        if status == "VALID": print(f"{GREEN}[{timestamp}] [{user_tag}] ✅ {code} | VALID | {msg}{RESET}")
        elif status == "REDEEMED": print(f"{BLUE}[{timestamp}] [{user_tag}] 🔄 {code} | REDEEMED{RESET}")
        elif status == "USED": print(f"{YELLOW}[{timestamp}] [{user_tag}] ⚠️ {code} | USED{RESET}")
        elif status == "INVALID": print(f"{RED}[{timestamp}] [{user_tag}] ❌ {code} | INVALID | {msg}{RESET}")
        else: print(f"{CYAN}[{timestamp}] [{user_tag}] ℹ️ {code} | {status} | {msg}{RESET}")

def check_internet():
    while True:
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError: time.sleep(5)

def send_temp_file(chat_id, filename, lines):
    """Creates a temporary file, sends it, and deletes it."""
    if not lines: return
    temp_name = f"{chat_id}_{filename}"
    try:
        with open(temp_name, "w") as f:
            f.write("\n".join(lines))
        with open(temp_name, "rb") as f:
            bot.send_document(chat_id, f, caption=f"📄 {filename} ({len(lines)})")
        os.remove(temp_name)
    except: pass

# ================= FILE OPERATIONS =================
def is_duplicate(code):
    for fname in FILES.values():
        if fname.endswith(".json"): continue
        if os.path.exists(fname):
            with open(fname, 'r') as f:
                if code in f.read(): return True
    return False

def save_cookies_global(data, filename):
    with file_lock:
        with open(filename, 'w') as f: json.dump(data, f, indent=4)

def load_cookies_global(filename):
    if not os.path.exists(filename): return None
    try:
        with file_lock:
            with open(filename, 'r') as f: 
                data = json.load(f)
                return "; ".join(f"{k}={v}" for k, v in data.items())
    except: return None

def get_account_info(filename):
    if not os.path.exists(filename): return "Not Logged In"
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            uid = data.get("U", "Unknown")
            return f"✅ Active ({uid})"
    except: return "❌ Corrupt Data"

def logout_slot(filename):
    if os.path.exists(filename): os.remove(filename)

def smart_append(filename, codes_list):
    if not codes_list: return
    with file_lock:
        existing = set()
        if os.path.exists(filename):
            with open(filename, "r") as f:
                existing = set([l.strip() for l in f if l.strip()])
        
        new_codes = [c for c in codes_list if c not in existing]
        
        if new_codes:
            with open(filename, "a") as f:
                f.write("\n".join(new_codes) + "\n")

# ================= LOGIN LOGIC =================
def get_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def get_android_headers(additional=None):
    headers = {
        'User-Agent': 'Android', 'Client_type': 'Android/29', 'Client_version': '1.0.8',
        'X-Tenant-Id': 'SHEIN', 'X-Tenant': 'B2C', 'Ad_id': AD_ID,
        'X-Forwarded-For': get_random_ip(), 'Host': 'api.sheinindia.in', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip'
    }
    if additional: headers.update(additional)
    return headers

def get_client_token(session):
    try:
        url = "https://api.sheinindia.in/uaas/jwt/token/client"
        headers = get_android_headers({'Content-Type': 'application/x-www-form-urlencoded'})
        data = "grantType=client_credentials&clientName=trusted_client&clientSecret=secret"
        resp = session.post(url, data=data, headers=headers)
        return resp.json().get('access_token') if resp.status_code == 200 else None
    except: return None

def send_otp(session, c_token, mobile):
    url = "https://api.sheinindia.in/uaas/login/sendOTP?client_type=Android%2F29&client_version=1.0.8"
    headers = get_android_headers({'Authorization': f'Bearer {c_token}', 'Content-Type': 'application/x-www-form-urlencoded'})
    resp = session.post(url, data=f"mobileNumber={mobile}", headers=headers)
    return resp.status_code == 200

def verify_otp_full(session, c_token, mobile, otp):
    url = "https://api.sheinindia.in/uaas/login/otp?client_type=Android%2F29&client_version=1.0.8"
    headers = get_android_headers({'Authorization': f'Bearer {c_token}', 'Content-Type': 'application/x-www-form-urlencoded'})
    params = {'adId': AD_ID, 'clientName': 'trusted_client', 'expireOTP': 'true', 'mobileNumber': 'true', 'otp': otp, 'clientSecret': 'secret', 'grantType': 'password', 'deviceId': str(uuid.uuid4()), 'username': mobile}
    resp = session.post(url, data=urlencode(params), headers=headers)
    try: return resp.json() if resp.status_code == 200 else None
    except: return None

def get_ei_token(session, client_token, phone_number):
    try:
        url = "https://api.sheinindia.in/uaas/accountCheck"
        headers = get_android_headers({'Authorization': f'Bearer {client_token}', 'Requestid': 'account_check', 'Content-Type': 'application/x-www-form-urlencoded'})
        resp = session.post(url, headers=headers, data=f'mobileNumber={phone_number}', params={'client_type': 'Android/29'}, timeout=10)
        res_json = resp.json()
        if 'encryptedId' in res_json: return res_json['encryptedId']
        return res_json.get('data', {}).get('encryptedId', "")
    except: return ""

def fetch_profile_uid(session, access_token):
    try:
        url = "https://api.sheinindia.in/uaas/users/current?client_type=Android%2F29&client_version=1.0.8"
        headers = get_android_headers({'Authorization': f'Bearer {access_token}', 'Requestid': 'UserProfile'})
        resp = session.get(url, headers=headers, timeout=10)
        data = resp.json()
        if 'uid' in data: return data['uid']
        return data.get('data', {}).get('uid')
    except: return None

def perform_global_login(trigger_user, mobile, otp, session, c_token, filename):
    print_console(trigger_user, "LOGIN", "INFO", f"Verifying OTP for {mobile}...")
    try:
        auth_data = verify_otp_full(session, c_token, mobile, otp)
        if auth_data and 'access_token' in auth_data:
            ei_value = get_ei_token(session, c_token, mobile)
            acc_token = auth_data.get('access_token')
            uid_value = fetch_profile_uid(session, acc_token)
            
            cookies_dict = {
                'V': '1', '_fpuuid': str(uuid.uuid4()).replace('-', '')[:21],
                'deviceId': str(uuid.uuid4()), 'storeTypes': 'shein', 'LS': 'LOGGED_IN',
                'C': str(uuid.uuid4()), 'EI': ei_value,
                'A': auth_data.get('access_token', ''),
                'U': uid_value if uid_value else f"{mobile}@sheinindia.in",
                'R': auth_data.get('refresh_token', '')
            }
            save_cookies_global(cookies_dict, filename)
            print_console(trigger_user, "LOGIN", "VALID", "Session Saved")
            return True
        else: return False
    except Exception as e:
        print_console(trigger_user, "LOGIN", "INVALID", f"Error: {e}")
        return False

# ================= CART & CHECK LOGIC =================
def update_headers_with_session(session, headers):
    try:
        session_cookies = session.cookies.get_dict()
        if not session_cookies: return headers
        current = headers.get('cookie', '')
        c_dict = {}
        if current:
            for item in current.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    c_dict[k] = v
        c_dict.update(session_cookies)
        headers['cookie'] = "; ".join(f"{k}={v}" for k, v in c_dict.items())
        return headers
    except: return headers

def ensure_global_cart(session, headers, cookie_file):
    try:
        r = robust_request(session, "GET", URL_MICROCART, headers=headers)
        update_headers_with_session(session, headers)
        if r.json().get("code"): return r.json().get("code")
    except: pass
    try:
        with file_lock:
             with open(cookie_file, "r") as f: email = json.load(f).get('U', 'Unknown')
        pl = {"user": quote(email).replace("%40", "%40"), "accessToken": ""}
        r = robust_request(session, "POST", URL_CREATE, headers=headers, json=pl)
        update_headers_with_session(session, headers)
        if r.json().get("code"): return r.json().get("code")
    except: pass
    return None

def check_code(session, code, headers, cart_id):
    try:
        url = "https://www.sheinindia.in/api/cart/apply-voucher"
        pl = {"voucherId": code, "cartId": cart_id, "device": {"client_type": "web"}}
        r = robust_request(session, "POST", url, json=pl, headers=headers, timeout=5)
        if r is None: return "RETRY", "Network"
        data = r.json()
        if data.get("statusCode") == "success" or "errorMessage" not in data: return "VALID", "Applied"
        
        errs = data.get("errorMessage", {}).get("errors", [])
        if not errs:
            msg = str(data).lower()
            if "not applicable" in msg: return "USED", "Not Applicable"
            return "INVALID", "Unknown"

        msg = errs[0].get("message", "").lower()
        if "redeemed" in msg or "limit" in msg or "busy" in msg: return "REDEEMED", "Redeemed/Limit"
        elif "not applicable" in msg: return "USED", "Not Applicable"
        else: return "INVALID", msg
    except Exception as e: return "RETRY", str(e)

def reset_voucher(session, code, headers):
    try: robust_request(session, "POST", "https://www.sheinindia.in/api/cart/reset-voucher", json={"voucherId": code, "device": {"client_type": "web"}}, headers=headers)
    except: pass

def robust_request(session, method, url, **kwargs):
    for _ in range(3):
        try:
            if method == "POST": return session.post(url, **kwargs)
            else: return session.get(url, **kwargs)
        except: time.sleep(0.5)
    return None

# ================= WORKER =================
def run_scan_worker(codes, trigger_user, mode, cookie_file):
    check_internet()
    c_str = load_cookies_global(cookie_file)
    if not c_str: return [], [], [], []

    session = requests.Session()
    headers = {
        "accept": "application/json", "content-type": "application/json",
        "origin": "https://www.sheinindia.in", "referer": "https://www.sheinindia.in/cart",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        "x-tenant-id": "SHEIN", "cookie": c_str
    }
    
    cart_id = ensure_global_cart(session, headers, cookie_file)
    if not cart_id: return [], [], [], []

    valid_res, redem_res, used_res, inv_res = [], [], [], []
    
    def process(code):
        if mode == "PROTECTION" and not protection_config["active"]: return None
        status, msg = check_code(session, code, headers, cart_id)
        
        if mode == "MANUAL":
            with print_lock:
                if live_monitor.get("stats"):
                    live_monitor["stats"]["checked"] = live_monitor["stats"].get("checked", 0) + 1
                    k = status.lower() 
                    live_monitor["stats"][k] = live_monitor["stats"].get(k, 0) + 1

        print_console(trigger_user, code, status, f"{msg} | {cookie_file}")
        
        if status == "VALID":
            reset_voucher(session, code, headers)
            return ("VALID", code)
        elif status == "REDEEMED": return ("REDEEMED", code)
        elif status == "USED": return ("USED", code)
        elif status == "INVALID": return ("INVALID", code)
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_code = {executor.submit(process, code): code for code in codes}
        for future in as_completed(future_to_code):
            try:
                result = future.result()
                if not result: continue
                status, code = result
                if status == "VALID": valid_res.append(code)
                elif status == "REDEEMED": redem_res.append(code)
                elif status == "USED": used_res.append(code)
                elif status == "INVALID": inv_res.append(code)
            except: pass
            
    return valid_res, redem_res, used_res, inv_res

# ================= SAFE MONITOR THREAD =================
def monitor_thread():
    while True:
        try:
            if live_monitor["active"] and live_monitor["msg_id"]:
                s = live_monitor.get("stats", {})
                txt = (
                    f"📟 **Live Check Monitor**\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"📉 **Progress:** {s.get('checked', 0)}/{s.get('total', 0)}\n"
                    f"✅ **Valid:** {s.get('valid', 0)}\n"
                    f"🔄 **Redeemed:** {s.get('redeemed', 0)}\n"
                    f"⚠️ **Used:** {s.get('used', 0)}\n"
                    f"❌ **Invalid:** {s.get('invalid', 0)}"
                )
                try:
                    bot.edit_message_text(txt, live_monitor["chat_id"], live_monitor["msg_id"], parse_mode="Markdown")
                except: pass
        except: pass
        time.sleep(2)

threading.Thread(target=monitor_thread, daemon=True).start()

# ================= PROTECTION LOOP =================
def global_protection_loop():
    print_console("SYSTEM", "PROT", "INFO", "Protection Loop Started")
    while True:
        try:
            if not protection_config["active"]:
                time.sleep(2)
                continue
                
            check_internet()
            
            targets = []
            if protection_config["mode"] == "REDEM":
                targets = [FILES["REDEM"]]
            else:
                targets = [FILES["REDEM"], FILES["SVI"], FILES["SVC"], FILES["SVD"], FILES["SVH"]]
                
            codes_to_check = []
            for t in targets:
                if os.path.exists(t):
                    with open(t, 'r') as f: codes_to_check.extend([l.strip() for l in f if l.strip()])
            
            codes_to_check = list(set(codes_to_check))
            
            if codes_to_check:
                print_console("SYSTEM", "PROT", "INFO", f"Checking {len(codes_to_check)} codes...")
                val, red, used, inv = run_scan_worker(codes_to_check, ADMIN_ID, "PROTECTION", FILES["COOKIES_1"])
                
                if not val and not red and not used and not inv:
                     val, red, used, inv = run_scan_worker(codes_to_check, ADMIN_ID, "PROTECTION", FILES["COOKIES_2"])

                for code in val:
                    smart_append(FILES.get(code[:3].upper()), [code])
                    try: bot.send_message(ADMIN_ID, f"🎉 **PROTECTION HIT!**\nCode `{code}` is now Valid!", parse_mode="Markdown")
                    except: pass
                
                smart_append(FILES["USED"], used)
                smart_append(FILES["INV"], inv)
                
                # Re-write Redem to keep only what is currently redeemed
                with open(FILES["REDEM"], "w") as f: f.write("\n".join(red) + "\n" if red else "")

            print_console("SYSTEM", "WAIT", "INFO", f"Sleeping {protection_config['interval']}s...")
            for _ in range(protection_config['interval']):
                if not protection_config["active"]: break
                time.sleep(1)
        except Exception as e:
            print(f"Protection Error: {e}")
            time.sleep(10)

# ================= TELEGRAM HANDLERS =================
def main_menu():
    m = types.ReplyKeyboardMarkup(resize_keyboard=True)
    m.add("🚀 Run Check", "➕ Add Codes")
    m.add("🛡️ Protector", "👤 Accounts")
    m.add("🔐 Login", "📊 Bot Status")
    return m

@bot.message_handler(commands=['start'])
def start(m):
    # Removed Permission Check -> Public Bot
    bot.send_message(m.chat.id, "🤖 **Shein Master V12**\nCheck & Send Files Support", reply_markup=main_menu(), parse_mode="Markdown")

# --- 1. Run Check ---
@bot.message_handler(func=lambda m: m.text == "🚀 Run Check")
def check_menu(m):
    mk = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    mk.add("🌍 Check ALL", "🔄 Check Redeemed")
    mk.add("💵 Check 500", "💵 Check 1k")
    mk.add("💵 Check 2k", "💵 Check 4k")
    mk.add("🔙 Back")
    user_states[m.chat.id] = {'step': 'chk_select'}
    bot.send_message(m.chat.id, "Select what to check:", reply_markup=mk)

# --- 2. Add Codes ---
@bot.message_handler(func=lambda m: m.text == "➕ Add Codes")
def add_codes(m):
    user_states[m.chat.id] = {'step': 'add_input'}
    bot.send_message(m.chat.id, "📝 **Paste Codes:**\n(Send Max 240 Codes )")

# --- 3. Protector ---
@bot.message_handler(func=lambda m: m.text == "🛡️ Protector")
def prot_menu(m):
    mk = types.ReplyKeyboardMarkup(resize_keyboard=True)
    state = "🟢 ON" if protection_config["active"] else "🔴 OFF"
    mk.add(f"Toggle: {state}")
    mk.add("⏱️ Set Time (30s)", "⏱️ Set Time (60s)")
    mk.add("⏱️ Set Time (5m)", "🎯 Mode: " + protection_config["mode"])
    mk.add("🔙 Back")
    bot.send_message(m.chat.id, f"🛡️ **Protection Settings**\nInterval: {protection_config['interval']}s", reply_markup=mk)

# --- 4. Accounts ---
@bot.message_handler(func=lambda m: m.text == "👤 Accounts")
def acc_menu(m):
    info1 = get_account_info(FILES["COOKIES_1"])
    info2 = get_account_info(FILES["COOKIES_2"])
    mk = types.ReplyKeyboardMarkup(resize_keyboard=True)
    mk.add("Logout Slot 1", "Logout Slot 2")
    mk.add("🔙 Back")
    bot.send_message(m.chat.id, f"👤 **Account Status**\n1️⃣ Slot 1: {info1}\n2️⃣ Slot 2: {info2}", reply_markup=mk, parse_mode="Markdown")

# --- 5. Status ---
@bot.message_handler(func=lambda m: m.text == "📊 Bot Status")
def stats(m):
    counts = {}
    for k, v in FILES.items():
        if v.endswith(".txt") and os.path.exists(v):
            with open(v, 'r') as f: counts[k] = len(f.readlines())
    
    msg = "**Database Stats:**\n"
    for k, c in counts.items(): msg += f"{k}: {c}\n"
    msg += f"\nProt: {protection_config['active']} ({protection_config['interval']}s)"
    bot.send_message(m.chat.id, msg, parse_mode="Markdown")

# --- 6. Input Logic ---
@bot.message_handler(content_types=['text'])
def logic(m):
    cid = m.chat.id
    st = user_states.get(cid, {})
    step = st.get('step')
    text = m.text
    
    if text == "🔙 Back":
        user_states[cid] = {}
        bot.send_message(cid, "Main Menu", reply_markup=main_menu())
        return

    # Prot Logic
    if text.startswith("Toggle:"):
        protection_config["active"] = not protection_config["active"]
        save_system_state()
        prot_menu(m)
        return
    elif "Set Time" in text:
        if "30s" in text: protection_config["interval"] = 30
        elif "60s" in text: protection_config["interval"] = 60
        elif "5m" in text: protection_config["interval"] = 300
        save_system_state()
        bot.send_message(cid, f"✅ Interval set to {protection_config['interval']}s")
        return
    elif "Mode:" in text:
        protection_config["mode"] = "ALL" if protection_config["mode"] == "REDEM" else "REDEM"
        save_system_state()
        prot_menu(m)
        return

    # Account Logic
    if text == "Logout Slot 1":
        logout_slot(FILES["COOKIES_1"])
        bot.send_message(cid, "✅ Slot 1 Logged Out.")
        return
    elif text == "Logout Slot 2":
        logout_slot(FILES["COOKIES_2"])
        bot.send_message(cid, "✅ Slot 2 Logged Out.")
        return

    # Check Logic
    if step == 'chk_select':
        target_files = []
        if text == "🌍 Check ALL": target_files = [FILES["REDEM"], FILES["SVI"], FILES["SVC"], FILES["SVD"], FILES["SVH"]]
        elif text == "🔄 Check Redeemed": target_files = [FILES["REDEM"]]
        elif text == "💵 Check 500": target_files = [FILES["SVI"]]
        elif text == "💵 Check 1k": target_files = [FILES["SVC"]]
        elif text == "💵 Check 2k": target_files = [FILES["SVD"]]
        elif text == "💵 Check 4k": target_files = [FILES["SVH"]]
        
        codes = []
        for t in target_files:
            if os.path.exists(t):
                with open(t, 'r') as f: codes.extend([l.strip() for l in f if l.strip()])
        
        codes = list(set(codes))
        if not codes:
            bot.send_message(cid, "❌ No codes found.")
            return
            
        global live_monitor
        msg = bot.send_message(cid, "🚀 **Starting Check...**")
        
        live_monitor = {
            "active": True, "msg_id": msg.message_id, "chat_id": cid, 
            "stats": {"total": len(codes), "checked": 0, "valid": 0, "redeemed": 0, "used": 0, "invalid": 0}
        }
        
        def run_chk():
            val, red, used, inv = run_scan_worker(codes, cid, "MANUAL", FILES["COOKIES_1"])
            for c in val: smart_append(FILES.get(c[:3].upper()), [c])
            smart_append(FILES["USED"], used)
            smart_append(FILES["INV"], inv)
            
            if text in ["🔄 Check Redeemed", "🌍 Check ALL"]:
                with open(FILES["REDEM"], "w") as f: f.write("\n".join(red) + "\n" if red else "")
            else:
                smart_append(FILES["REDEM"], red)
            
            live_monitor["active"] = False
            bot.send_message(cid, f"✅ **Check Complete.**\nValid: {len(val)}\nRedeemed: {len(red)}\nUsed: {len(used)}", reply_markup=main_menu())

        threading.Thread(target=run_chk).start()
        user_states[cid] = {}

    # Add Logic
    elif step == 'add_input':
        raw = [l.strip() for l in text.split('\n') if l.strip()]
        
        user_states[cid] = {'step': 'add_confirm', 'codes': raw}
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔍 Check Only", callback_data="chk_only"),
                   types.InlineKeyboardButton("💾 Check & Save", callback_data="chk_save"))
        
        bot.send_message(cid, f"❓ Found {len(raw)} codes. max 240 per check?", reply_markup=markup)

    # Login Logic
    elif text == "🔐 Login":
        mk = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
        mk.add("Slot 1", "Slot 2", "🔙 Back")
        user_states[cid] = {'step': 'slot_sel'}
        bot.send_message(cid, "Select Slot:", reply_markup=mk)
        
    elif step == 'slot_sel':
        tf = FILES["COOKIES_1"] if "Slot 1" in text else FILES["COOKIES_2"]
        user_states[cid] = {'step': 'mob', 'target': tf}
        bot.send_message(cid, "📱 Enter Mobile:", reply_markup=types.ReplyKeyboardRemove())
        
    elif step == 'mob':
        mobile = text.strip()
        sess = requests.Session()
        try:
            ct = get_client_token(sess)
            if ct and send_otp(sess, ct, mobile):
                user_states[cid].update({'step': 'otp', 'mob': mobile, 'sess': sess, 'ct': ct})
                bot.send_message(cid, "✅ OTP Sent.")
            else: bot.send_message(cid, "❌ Failed.")
        except: bot.send_message(cid, "❌ Error.")
        
    elif step == 'otp':
        d = user_states[cid]
        if perform_global_login(cid, d['mob'], text.strip(), d['sess'], d['ct'], d['target']):
            bot.send_message(cid, "✅ Logged In!", reply_markup=main_menu())
        else: bot.send_message(cid, "❌ Failed.", reply_markup=main_menu())
        user_states[cid] = {}

# --- Callback for Add Logic (UPDATED) ---
@bot.callback_query_handler(func=lambda call: call.data in ["chk_only", "chk_save"])
def add_callback(call):
    cid = call.message.chat.id
    st = user_states.get(cid, {})
    codes = st.get('codes', [])
    
    if not codes:
        bot.answer_callback_query(call.id, "❌ Session expired.")
        return

    # Duplicate check only if Saving
    if call.data == "chk_save":
        uniq = []
        dups = 0
        for c in codes:
            if is_duplicate(c): dups += 1
            else: uniq.append(c)
        codes = uniq
        if not codes:
            bot.send_message(cid, f"❌ All {dups} codes were duplicates.", reply_markup=main_menu())
            user_states[cid] = {}
            return
            
    bot.edit_message_text(f"🚀 Processing {len(codes)} codes...", cid, call.message.message_id)
    
    global live_monitor
    live_monitor = {
        "active": True, "msg_id": call.message.message_id, "chat_id": cid, 
        "stats": {"total": len(codes), "checked": 0, "valid": 0, "redeemed": 0, "used": 0, "invalid": 0}
    }

    def run_cb():
        val, red, used, inv = run_scan_worker(codes, cid, "MANUAL", FILES["COOKIES_1"])
        
        live_monitor["active"] = False # Stop monitor early to send files/final msg
        
        if call.data == "chk_save":
            for c in val: smart_append(FILES.get(c[:3].upper()), [c])
            smart_append(FILES["REDEM"], red)
            smart_append(FILES["USED"], used)
            smart_append(FILES["INV"], inv)
            title = "💾 **Saved Results:**"
            bot.send_message(cid, f"{title}\nValid: {len(val)}\nRedeemed: {len(red)}\nUsed: {len(used)}\nInvalid: {len(inv)}", reply_markup=main_menu())
        else:
            title = "🔍 **Scan Results (Files Sent):**"
            # Send Files Logic
            send_temp_file(cid, "valid.txt", val)
            send_temp_file(cid, "redem.txt", red)
            send_temp_file(cid, "used.txt", used)
            bot.send_message(cid, f"{title}\nValid: {len(val)}\nRedeemed: {len(red)}\nUsed: {len(used)}\nInvalid: {len(inv)}", reply_markup=main_menu())

    threading.Thread(target=run_cb).start()
    user_states[cid] = {}

if __name__ == "__main__":
    load_system_state()
    if protection_config["active"]: threading.Thread(target=global_protection_loop, daemon=True).start()
    print("✅ Bot Online (Crash Proof & Public)")
    
    # CRASH PROOF MAIN LOOP
    while True:
        try:
            check_internet()
            bot.polling(none_stop=True, timeout=60, long_polling_timeout=60)
        except Exception as e:
            print(f"CRASH: {e}")
            time.sleep(5)
            print("Restarting...")
