from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii, aiohttp, requests, json
import like_pb2, like_count_pb2, uid_generator_pb2
import time, random, os, jwt, threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== CREDITS =====
CHANNEL = "@ayantcplab"
CREDIT  = "@ayan_bro222"
GROUP   = "@mia khalifa"

TOKEN_CACHE = {}
app = Flask(__name__)

KEY_LIMIT = 100
tracker = defaultdict(lambda: [0, time.time()])
liked_cache = defaultdict(set)

# ===== TOKEN FILES =====
TOKEN_FILES = {
    "IND": "token_ind.json",
    "BR":  "token_br.json",
    "BD":  "token_bd.json",
    "RU":  "token_ru.json",
}
ACCOUNT_FILES = {
    "IND": "account_ind.txt",
    "BR":  "account_br.txt",
    "BD":  "account_bd.txt",
    "RU":  "account_ru.txt",
}

URLS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BR":  "https://client.us.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "NA":  "https://client.us.freefiremobile.com",
    "BD":  "https://clientbp.ppmainecoonghj.com",
    "RU":  "https://client.ru.freefiremobile.com",
}
JWT_API = "http://node54.lunes.host:3069/token"

UA = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
XGA_SV = "1789556611"
UNITY_V = "2018.4.12f1"
REL_V = "OB55"

JWT_CONCURRENCY     = 50
LIKE_CONCURRENCY    = 50
JWT_TIMEOUT         = 30

CHECK_INTERVAL_MIN  = 30
TOKEN_MIN_VALIDITY  = 1800

def midnight():
    n = datetime.now()
    return datetime(n.year, n.month, n.day).timestamp()

def is_placeholder(u, p):
    bad = {"uid", "password", "user", "pass", "your_uid", "your_password"}
    return u.lower() in bad or p.lower() in bad

def load_file(fn):
    accs = []
    seen = set()
    if not os.path.exists(fn):
        return accs
    try:
        with open(fn) as f:
            for l in f:
                l = l.strip()
                if not l or l.startswith('#'):
                    continue
                if ':' in l:
                    u, p = l.split(':', 1)
                    u, p = u.strip(), p.strip()
                    if not u or not p or is_placeholder(u, p):
                        continue
                    if u not in seen:
                        seen.add(u)
                        accs.append({"uid": u, "password": p})
    except Exception:
        pass
    return accs

def load_accounts(s):
    if s in {"BR","US","SAC","NA"}:
        primary = "account_br.txt"
    elif s == "IND":
        primary = "account_ind.txt"
    elif s == "BD":
        primary = "account_bd.txt"
    elif s == "RU":
        primary = "account_ru.txt"
    else:
        primary = "account_ind.txt"
    a = load_file(primary)
    if a:
        print(f"Loaded {len(a)} accounts from {primary} for {s}")
        return a
    for fb in ["account_ind.txt", "account_br.txt", "account_bd.txt", "account_ru.txt"]:
        if fb == primary:
            continue
        a = load_file(fb)
        if a:
            print(f"⚠️ Fallback: loaded {len(a)} accounts from {fb} for {s}")
            return a
    return []

def load_accounts_by_file():
    result = {}
    for srv, fn in ACCOUNT_FILES.items():
        a = load_file(fn)
        if a:
            result[srv] = a
    return result

def save_tokens_for_server(server, uids):
    fname = TOKEN_FILES.get(server)
    if not fname:
        return False
    try:
        tokens = {}
        for uid in uids:
            c = TOKEN_CACHE.get(uid)
            if not c:
                continue
            tokens[uid] = {
                "token": c.get("token"),
                "expires_at": c["expires_at"].isoformat() if isinstance(c.get("expires_at"), datetime) else str(c.get("expires_at")),
                "login_url": c.get("login_url"),
                "region": c.get("region"),
                "fetched_at": c.get("fetched_at"),
            }
        data = {
            "server": server,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(tokens),
            "tokens": tokens,
        }
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        print(f"💾 Saved {len(tokens)} tokens → {fname}")
        return True
    except Exception as e:
        print(f"⚠️ Failed to save {fname}: {e}")
        return False

def load_tokens_from_file(server):
    fname = TOKEN_FILES.get(server)
    if not fname or not os.path.exists(fname):
        return 0
    try:
        with open(fname) as f:
            data = json.load(f)
        now = datetime.now(timezone.utc)
        loaded = 0
        skipped = 0
        for uid, c in (data.get("tokens") or {}).items():
            try:
                exp = datetime.fromisoformat(c["expires_at"])
                if (exp - now).total_seconds() > TOKEN_MIN_VALIDITY:
                    TOKEN_CACHE[uid] = {
                        "token": c["token"],
                        "expires_at": exp,
                        "login_url": c.get("login_url"),
                        "region": c.get("region"),
                        "fetched_at": c.get("fetched_at", time.time()),
                    }
                    loaded += 1
                else:
                    skipped += 1
            except Exception:
                continue
        print(f"📂 Loaded {loaded} tokens from {fname} (skipped {skipped} expired)")
        return loaded
    except Exception as e:
        print(f"⚠️ Failed to load {fname}: {e}")
        return 0

def load_all_tokens_from_files():
    total = 0
    for srv in TOKEN_FILES.keys():
        total += load_tokens_from_file(srv)
    return total

async def fetch_raw(session, uid, pwd):
    try:
        url = f"{JWT_API}?uid={uid}&password={pwd}"
        async with session.get(url, timeout=JWT_TIMEOUT) as r:
            if r.status != 200:
                return None
            d = await r.json()
            if not isinstance(d, dict) or not d.get("Success", True):
                return None
            return d
    except Exception:
        return None

def token_is_valid(uid):
    c = TOKEN_CACHE.get(uid)
    if not c:
        return False
    try:
        remaining = (c["expires_at"] - datetime.now(timezone.utc)).total_seconds()
        return remaining > TOKEN_MIN_VALIDITY
    except Exception:
        return False

def token_time_left(uid):
    c = TOKEN_CACHE.get(uid)
    if not c:
        return -1
    try:
        return (c["expires_at"] - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        return -1

async def get_valid_token(session, uid, pwd, force=False):
    if not force and token_is_valid(uid):
        return TOKEN_CACHE[uid]["token"]
    d = await fetch_raw(session, uid, pwd)
    if not d:
        return None
    t = d.get("Jwt_Token") or d.get("jwt_token") or d.get("token")
    if not t or t == "N/A":
        return None
    try:
        p = jwt.decode(t, options={"verify_signature": False})
        exp = datetime.fromtimestamp(p["exp"], tz=timezone.utc)
    except Exception:
        exp = datetime.now(timezone.utc) + timedelta(hours=8)
    TOKEN_CACHE[uid] = {
        "token": t,
        "expires_at": exp,
        "login_url": d.get("Login_url"),
        "region": d.get("Region"),
        "fetched_at": time.time(),
    }
    return t

def encrypt_msg(pt):
    c = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return binascii.hexlify(c.encrypt(pad(pt, AES.block_size))).decode()

def make_pb(uid, region):
    m = like_pb2.like()
    m.uid = int(uid)
    m.region = region
    return m.SerializeToString()

async def send_like(session, enc_uid, token, url):
    try:
        h = {
            'User-Agent': UA, 'Accept': "*/*", 'Accept-Encoding': "deflate, gzip",
            'X-GA-SV': XGA_SV, 'Authorization': f"Bearer {token}", 'X-GA': "v1 1",
            'ReleaseVersion': REL_V, 'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': UNITY_V
        }
        async with session.post(url, data=bytes.fromhex(enc_uid), headers=h, timeout=10) as r:
            return r.status
    except Exception:
        return 500

def region_of(login_url, region_field):
    if region_field:
        r = str(region_field).upper()
        if r in URLS:
            return r
    if not login_url:
        return None
    l = login_url.lower()
    if "client.ind" in l: return "IND"
    if "client.us" in l: return "US"
    if "client.ru" in l: return "RU"
    if "clientbp" in l or "client.bd" in l: return "BD"
    return None

def region_matches(acc_region, target):
    if not acc_region:
        return True
    if target == "IND": return acc_region == "IND"
    if target == "BD": return acc_region == "BD"
    if target == "RU": return acc_region == "RU"
    if target in {"BR","US","SAC","NA"}: return acc_region in {"BR","US","SAC","NA"}
    return True

async def prewarm_tokens(accs, server=None, force=False):
    need_fetch = []
    already_valid = []
    for a in accs:
        if not force and token_is_valid(a['uid']):
            already_valid.append(a)
        else:
            need_fetch.append(a)

    tag = server or "ALL"
    print(f"🔎 Prewarm[{tag}]: {len(already_valid)} cached valid, {len(need_fetch)} need fetch")

    valid_fetched = []
    if need_fetch:
        sem = asyncio.Semaphore(JWT_CONCURRENCY)
        connector = aiohttp.TCPConnector(limit=JWT_CONCURRENCY * 2, force_close=False)
        timeout = aiohttp.ClientTimeout(total=JWT_TIMEOUT)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async def one(a):
                async with sem:
                    t = await get_valid_token(session, a['uid'], a['password'], force=force)
                    if not t:
                        return None
                    return a
            results = await asyncio.gather(*[one(a) for a in need_fetch], return_exceptions=True)
        valid_fetched = [r for r in results if isinstance(r, dict)]

    combined = already_valid + valid_fetched

    if server is not None:
        filtered = []
        for a in combined:
            c = TOKEN_CACHE.get(a['uid']) or {}
            if region_matches(region_of(c.get("login_url"), c.get("region")), server):
                filtered.append(a)
        combined = filtered

    print(f"✅ Prewarm[{tag}]: {len(combined)}/{len(accs)} valid")
    return combined

async def broadcast_likes(target, server, url, valid_accs):
    pb = make_pb(target, server)
    enc_uid = encrypt_msg(pb)
    done = liked_cache.get(target, set())
    fresh = [a for a in valid_accs if a['uid'] not in done]
    if not fresh:
        return {"success": 0, "failed": 0}
    random.shuffle(fresh)
    sem = asyncio.Semaphore(LIKE_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=LIKE_CONCURRENCY * 2, force_close=False)
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def one(a):
            async with sem:
                c = TOKEN_CACHE.get(a['uid']) or {}
                ep = f"{c['login_url'].rstrip('/')}/LikeProfile" if c.get("login_url") else url
                tok = c.get("token")
                if not tok:
                    return 500
                st = await send_like(session, enc_uid, tok, ep)
                if st == 200:
                    liked_cache[target].add(a['uid'])
                return st
        results = await asyncio.gather(*[one(a) for a in fresh], return_exceptions=True)
    ok = sum(1 for r in results if r == 200)
    return {"success": ok, "failed": len(results) - ok}

def enc(uid):
    m = uid_generator_pb2.uid_generator()
    fs = list(m.DESCRIPTOR.fields)
    setattr(m, fs[0].name, int(uid))
    if len(fs) > 1:
        setattr(m, fs[1].name, 1)
    return encrypt_msg(m.SerializeToString())

def decode(b):
    try:
        i = like_count_pb2.Info()
        i.ParseFromString(b)
        return i
    except Exception:
        return None

def get_info(enc_uid, server, token):
    url = URLS.get(server, URLS["IND"])
    h = {
        'User-Agent': UA, 'Accept': "*/*", 'Accept-Encoding': "deflate, gzip",
        'X-GA-SV': XGA_SV, 'Authorization': f"Bearer {token}", 'X-GA': "v1 1",
        'ReleaseVersion': REL_V, 'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': UNITY_V
    }
    try:
        r = requests.post(f"{url}/GetPlayerPersonalShow", data=bytes.fromhex(enc_uid), headers=h, verify=False, timeout=10)
        return decode(r.content)
    except Exception:
        return None

def refresh_expired_tokens():
    grouped = load_accounts_by_file()
    if not grouped:
        print("⚠️ No account files found")
        return 0

    total_refreshed = 0
    for srv, accs in grouped.items():
        expired = [a for a in accs if not token_is_valid(a['uid'])]
        if not expired:
            print(f"✅ {srv}: all {len(accs)} tokens valid — skip")
            continue

        truly_expired = [a for a in expired if token_time_left(a['uid']) <= 0]
        near_expiry   = [a for a in expired if 0 < token_time_left(a['uid']) <= TOKEN_MIN_VALIDITY]
        print(f"🔄 {srv}: {len(truly_expired)} expired, {len(near_expiry)} expiring soon — refreshing {len(expired)}")

        t0 = time.time()
        valid = asyncio.run(prewarm_tokens(expired, server=None, force=False))
        dt = round(time.time() - t0, 2)
        print(f"✅ {srv} refreshed — {len(valid)}/{len(expired)} valid in {dt}s")

        uids = [a['uid'] for a in accs if a['uid'] in TOKEN_CACHE]
        save_tokens_for_server(srv, uids)
        total_refreshed += len(valid)
    return total_refreshed

def scheduler_loop():
    loaded = load_all_tokens_from_files()
    print(f"📂 Total loaded from files: {loaded}")

    if loaded == 0:
        print("⚠️ No cached tokens — initial fetch needed")
        try:
            refresh_expired_tokens()
        except Exception as e:
            print(f"⚠️ Initial fetch failed: {e}")

    while True:
        time.sleep(CHECK_INTERVAL_MIN * 60)
        try:
            print(f"⏰ {CHECK_INTERVAL_MIN}min check — scanning for expired tokens...")
            refresh_expired_tokens()
        except Exception as e:
            print(f"⚠️ Scheduled check failed: {e}")

@app.route('/like')
def like():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    ip = request.remote_addr

    if not uid or not server:
        return jsonify({"error": "UID and server_name required"}), 400
    if server not in URLS:
        return jsonify({"error": f"Invalid server. Use: {list(URLS.keys())}"}), 400

    accs = load_accounts(server)
    if not accs:
        return jsonify({"error": f"No accounts available for {server}"}), 500

    mid = midnight()
    cnt, lr = tracker[ip]
    if lr < mid:
        tracker[ip] = [0, time.time()]
        cnt = 0
    if cnt >= KEY_LIMIT:
        return jsonify({"error": "Daily limit reached", "remains": f"(0/{KEY_LIMIT})"}), 429

    t0 = time.time()

    valid_accs = asyncio.run(prewarm_tokens(accs, server=server, force=False))
    if not valid_accs:
        return jsonify({"error": f"No valid {server} accounts"}), 500

    tok = TOKEN_CACHE[valid_accs[0]['uid']]['token']
    enc_uid = enc(uid)

    b = get_info(enc_uid, server, tok)
    if b is None:
        return jsonify({"error": "Invalid UID or server mismatch", "status": 0}), 200
    try:
        bd = json.loads(MessageToJson(b))
        bl = int(bd['AccountInfo'].get('Likes', 0))
    except Exception:
        return jsonify({"error": "Parse failed", "status": 0}), 200

    like_url = f"{URLS[server]}/LikeProfile"
    stats = asyncio.run(broadcast_likes(uid, server, like_url, valid_accs))

    a = get_info(enc_uid, server, tok)
    if a is None:
        return jsonify({"error": "Verify failed", "status": 0}), 200
    try:
        ad = json.loads(MessageToJson(a))
        al = int(ad['AccountInfo']['Likes'])
        pid = int(ad['AccountInfo']['UID'])
        pn = str(ad['AccountInfo']['PlayerNickname'])
        given = al - bl
        st = 1 if given != 0 else 2
        if given > 0:
            tracker[ip][0] += 1
            cnt += 1
        return jsonify({
            "LikesGivenByAPI": given,
            "LikesafterCommand": al,
            "LikesbeforeCommand": bl,
            "PlayerNickname": pn,
            "Server": server,
            "UID": pid,
            "status": st,
            "Elapsed sec": round(time.time() - t0, 2),
            "tokens_used": stats.get("success", 0),
            "remains": f"({KEY_LIMIT - cnt}/{KEY_LIMIT})",
            "Credit": f"🔥 Ayan Bro | {CHANNEL}"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

@app.route('/reset-limit')
def reset_limit():
    ip = request.remote_addr
    tracker[ip] = [0, time.time()]
    return jsonify({
        "message": "Limit reset",
        "ip": ip,
        "remains": f"({KEY_LIMIT}/{KEY_LIMIT})"
    })

if __name__ == '__main__':
    print("🔥 Ayan Bro Like API — Server Starting")
    print(f"📢 Channel : {CHANNEL}")
    print(f"👤 Credit  : {CREDIT}")
    print(f"Supported servers: {list(URLS.keys())}")
    print(f"Speed: JWT={JWT_CONCURRENCY}x, LIKE={LIKE_CONCURRENCY}x")
    print(f"Token check: every {CHECK_INTERVAL_MIN} min")
    
    # ব্যাকগ্রাউন্ডে টোকেন আপডেটের থ্রেড চালু
    threading.Thread(target=scheduler_loop, daemon=True).start()
    
    # Render নিজে থেকেই PORT ধরে নিবে, না পেলে 5001 এ চলবে
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
