#!/usr/bin/env python3
"""TLR REST 的 OAuth 登入範例（純標準函式庫，Python 3.9+）。

流程：discovery → 動態註冊 client → 開瀏覽器到授權頁（會轉到法律偵探登入頁）→
本機 127.0.0.1 接回授權碼 → 換 access token／refresh token → 存檔 → 帶 Bearer 呼叫 /v1/*。
access token 一小時過期，用 refresh token 換新的；持續使用不必再登入，閒置 30 天才要。

用法：
  python3 tlr_oauth_cli.py login            # 第一次：開瀏覽器登入
  python3 tlr_oauth_cli.py law 民法 184      # 之後：直接查，token 自動更新
  python3 tlr_oauth_cli.py search "租賃押金返還"
  加 --no-browser 只印網址，自己貼到瀏覽器。
"""
import base64, hashlib, http.server, json, os, secrets, sys, threading, time, urllib.parse, urllib.request, webbrowser

BASE = os.environ.get("TLR_BASE_URL", "https://tlr.dr-legal.com.tw")
STORE = os.path.expanduser(os.environ.get("TLR_OAUTH_STORE", "~/.twlegalrag/tlr_oauth.json"))
CLIENT_NAME = os.environ.get("TLR_CLIENT_NAME", "my-tlr-script")
UA = f"{CLIENT_NAME}/0.1 (+tlr-oauth-example)"  # 請用能辨識你程式的 UA；預設 Python-urllib 會被邊緣防護擋下


def _post(url, data, form=False, bearer=None):
    body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", "application/x-www-form-urlencoded" if form else "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _load():
    try:
        return json.load(open(STORE))
    except Exception:
        return {}


def _save(d):
    os.makedirs(os.path.dirname(STORE), exist_ok=True)
    tmp = STORE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STORE)


def login(open_browser=True):
    meta = _get(f"{BASE}/.well-known/oauth-authorization-server")
    store = _load()
    if not store.get("client_id"):
        # 本機回呼埠先佔下來，註冊時就要寫進 redirect_uris
        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    else:
        srv = http.server.HTTPServer(("127.0.0.1", store.get("port", 0)), _Handler)
    port = srv.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    if not store.get("client_id") or store.get("port") != port:
        st, reg = _post(meta["registration_endpoint"], {
            "client_name": CLIENT_NAME, "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none", "scope": "judgments:read"})
        if st != 201:
            sys.exit(f"client 註冊失敗 {st}: {reg}")
        store = {"client_id": reg["client_id"], "port": port}
        _save(store)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)
    url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": store["client_id"], "redirect_uri": redirect_uri,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "resource": f"{BASE}/mcp", "scope": "judgments:read"})
    print("請在瀏覽器完成法律偵探登入（30 分鐘內）：\n" + url, file=sys.stderr)
    if open_browser:
        webbrowser.open(url)
    _Handler.result = None
    srv.timeout = 1800
    t0 = time.time()
    while _Handler.result is None and time.time() - t0 < 1800:
        srv.handle_request()
    srv.server_close()
    if not _Handler.result or _Handler.result.get("state") != state:
        sys.exit("沒有收到授權碼（逾時、取消或 state 不符）")
    if "error" in _Handler.result:
        sys.exit(f"授權被拒：{_Handler.result['error']}")
    st, tok = _post(meta["token_endpoint"], {
        "grant_type": "authorization_code", "code": _Handler.result["code"], "code_verifier": verifier,
        "redirect_uri": redirect_uri, "client_id": store["client_id"]}, form=True)
    if st != 200:
        sys.exit(f"換 token 失敗 {st}: {tok}")
    store.update({"access_token": tok["access_token"], "refresh_token": tok["refresh_token"],
                  "expires_at": int(time.time()) + int(tok.get("expires_in", 3600)), "token_endpoint": meta["token_endpoint"]})
    _save(store)
    print("登入完成，token 已存到", STORE, file=sys.stderr)
    return store


class _Handler(http.server.BaseHTTPRequestHandler):
    result = None

    def do_GET(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        if self.path.startswith("/callback"):
            _Handler.result = q
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
            self.wfile.write("<meta charset=utf-8><p>TLR 登入完成，可以關閉這個分頁。</p>".encode())
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):
        pass


def access_token():
    s = _load()
    if not s.get("refresh_token"):
        return login()["access_token"]
    if s.get("expires_at", 0) - time.time() > 60:
        return s["access_token"]
    st, tok = _post(s["token_endpoint"], {"grant_type": "refresh_token", "refresh_token": s["refresh_token"],
                                          "client_id": s["client_id"]}, form=True)
    if st != 200:  # 閒置超過 30 天會到這裡：重新登入一次
        print("refresh 失敗，重新登入", file=sys.stderr)
        return login()["access_token"]
    s.update({"access_token": tok["access_token"], "expires_at": int(time.time()) + int(tok.get("expires_in", 3600))})
    _save(s)
    return s["access_token"]


def call(path, payload):
    st, body = _post(f"{BASE}{path}", payload, bearer=access_token())
    return st, body


if __name__ == "__main__":
    args = sys.argv[1:]
    nb = "--no-browser" in args
    args = [a for a in args if a != "--no-browser"]
    cmd = args[0] if args else "login"
    if cmd == "login":
        login(open_browser=not nb)
    elif cmd == "law":
        print(json.dumps(call("/v1/law_article", {"law_name": args[1], "article_no": args[2]})[1], ensure_ascii=False, indent=1)[:1500])
    elif cmd == "search":
        print(json.dumps(call("/v1/search", {"query": args[1], "max_results": 3})[1], ensure_ascii=False, indent=1)[:1500])
    else:
        sys.exit(__doc__)
