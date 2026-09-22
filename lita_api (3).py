#!/usr/bin/env python3
"""Lita API client -- standalone Python3 (no WASM, no Node).

Membungkus 10 endpoint h-api.lita.game yang sudah diverifikasi HTTP 200.
Signature l-sign dibuat langsung di modul ini (pure Python, reverse-engineered
from stable.wasm).

Pemakaian singkat
-----------------
    from lita_api import LitaClient

    c = LitaClient()          # pakai ACCESS_TOKEN default (capture)
    c.init()                  # bootstrap l-user-token dari /h5/init

    print(c.get_game_panel())
    print(c.diamond_jackpot_enter_game())
    print(c.user_account())

Atau langsung tanpa class:
    import lita_api
    lita_api.init()
    print(lita_api.get_game_panel())

Semua fungsi mengembalikan dict hasil json.loads() dari body respons.
Bila bukan JSON, mengembalikan string mentah.
"""

import hashlib
import json
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ═══════════════════════════════════════════════════════════════════════════════
# litasignv -- Standalone Python3 implementation of Lita `l-sign`
# ═══════════════════════════════════════════════════════════════════════════════
#
# The algorithm below was reconstructed by reverse engineering `stable.wasm`
# (AssemblyScript build, export `generateHeader`, wasm func[51] -> func[48]).
#
# Reconstructed pipeline
# ----------------------
# 1. A Map is built with the signing header fields (insertion order in wasm):
#
#        l-timestamp    -> timestamp
#        l-nonce        -> nonce
#        l-user-token   -> user_token   (ONLY if non-empty)
#        l-trace-id     -> trace_id
#        l-user-locale  -> locale
#        l-locale       -> locale
#        l-app-platform -> platform
#        l-app-id       -> app_id
#        l-accesstoken  -> access_token (ONLY if non-empty)
#
# 2. The map keys are sorted ascending (UTF-16 lexicographic string compare).
#
# 3. The map is serialized by concatenating `key + "=" + value` for every
#    entry in sorted order. Separator is '=' (0x3D), not ':'.
#
# 4. The request body is normalized: if body == "{}" it is replaced by ''.
#
# 5. Concatenation:
#        material = path + serialized_map + effective_body + SECRET_KEY
#
# 6. material is UTF-8 encoded, then hashed with MD5.
#
# 7. The 16-byte digest is hex-encoded lowercase.
#
# 8. l-sign = hexdigest[3:18]  (15 hex chars).
#
# Verification
# ------------
# GET /h5/init
# l-timestamp: 1789133602964
# l-nonce:     d86Go65noUlOTwRr
# l-trace-id:  d68404721b0f3a3b24b75bf02ae3fabd
# l-app-platform: 3
# l-locale:      id-ID
# l-user-locale: id-ID
# l-app-id:      Lita
# => l-sign: 082bd3f2b573213

# Secret extracted from stable.wasm @2808 (UTF-16LE string).
SECRET_KEY = "ckr1CP0Scdzk/krV2qhFenU13TUuBLFjAj08PldnMtc="

# Wasm data @2928: the literal empty JSON object.
EMPTY_JSON_OBJECT = "{}"

# API endpoint configuration
API_SCHEME = "https"
API_HOST = "h-api.lita.game"

# Signed header field names, in wasm map-insertion order.
SIGNED_FIELDS = (
    ("l-timestamp", "timestamp"),
    ("l-nonce", "nonce"),
    ("l-user-token", "user_token"),
    ("l-trace-id", "trace_id"),
    ("l-user-locale", "locale"),
    ("l-locale", "locale"),
    ("l-app-platform", "platform"),
    ("l-app-id", "app_id"),
    ("l-accesstoken", "access_token"),
)


def _as_text(value):
    """Normalize a value to str. None -> ''."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _build_field_map(
    timestamp,
    nonce,
    trace_id,
    locale,
    platform,
    app_id,
    user_token="",
    access_token="",
):
    """Build the signing map exactly like generateHeader() does."""
    timestamp = _as_text(timestamp)
    nonce = _as_text(nonce)
    trace_id = _as_text(trace_id)
    locale = _as_text(locale)
    platform = _as_text(platform)
    app_id = _as_text(app_id)
    user_token = _as_text(user_token)
    access_token = _as_text(access_token)

    values = {
        "timestamp": timestamp,
        "nonce": nonce,
        "trace_id": trace_id,
        "locale": locale,
        "platform": platform,
        "app_id": app_id,
        "user_token": user_token,
        "access_token": access_token,
    }

    fields = {}
    for field_name, arg_name in SIGNED_FIELDS:
        value = values[arg_name]
        if field_name in ("l-user-token", "l-accesstoken") and value == "":
            continue
        fields[field_name] = value
    return fields


def _serialize_map(fields):
    """Serialize map as concatenated `key=value` entries, keys sorted asc."""
    return "".join(
        "%s=%s" % (key, fields[key]) for key in sorted(fields)
    )


def _normalize_body(body):
    """Wasm replaces the literal '{}' body with the empty string."""
    body = _as_text(body)
    if body == EMPTY_JSON_OBJECT:
        return ""
    return body


def sign_material(path, fields, body=""):
    """Return the exact pre-hash string (path + map + body + secret)."""
    return (
        _as_text(path)
        + _serialize_map(fields)
        + _normalize_body(body)
        + SECRET_KEY
    )


def generate_header(
    path,
    timestamp,
    nonce,
    trace_id,
    locale="id-ID",
    platform="3",
    app_id="Lita",
    user_token="",
    access_token="",
    body="",
):
    """Compute the 15-char hex `l-sign` for a Lita request."""
    fields = _build_field_map(
        timestamp=timestamp,
        nonce=nonce,
        trace_id=trace_id,
        locale=locale,
        platform=platform,
        app_id=app_id,
        user_token=user_token,
        access_token=access_token,
    )
    material = sign_material(path, fields, body)
    digest_hex = hashlib.md5(material.encode("utf-8")).hexdigest()
    return digest_hex[3:18]


def make_nonce(length=16):
    """Random nonce similar to the app's 16-char alphanumeric value."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def make_trace_id():
    """32-char lowercase hex trace id (like the captured request)."""
    return "%032x" % random.getrandbits(128)


def now_ms():
    """Current unix time in milliseconds, as text."""
    return str(int(time.time() * 1000))


def build_headers(
    path,
    timestamp=None,
    nonce=None,
    trace_id=None,
    locale="id-ID",
    platform="3",
    app_id="Lita",
    user_token="",
    access_token="",
    body="",
    extra_headers=None,
):
    """Build a complete signed header dict for a Lita API request."""
    timestamp = timestamp if timestamp is not None else now_ms()
    nonce = nonce if nonce is not None else make_nonce()
    trace_id = trace_id if trace_id is not None else make_trace_id()

    sign = generate_header(
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        trace_id=trace_id,
        locale=locale,
        platform=platform,
        app_id=app_id,
        user_token=user_token,
        access_token=access_token,
        body=body,
    )

    headers = {
        "l-timestamp": _as_text(timestamp),
        "l-nonce": _as_text(nonce),
        "l-trace-id": _as_text(trace_id),
        "l-app-platform": _as_text(platform),
        "l-locale": _as_text(locale),
        "l-user-locale": _as_text(locale),
        "l-app-id": _as_text(app_id),
        "l-sign": sign,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://h5.lita.game",
        "Referer": "https://h5.lita.game/",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.6099.230 Mobile Safari/537.36"
        ),
    }
    if user_token:
        headers["l-user-token"] = _as_text(user_token)
    if access_token:
        headers["l-accesstoken"] = _as_text(access_token)
    if extra_headers:
        headers.update(extra_headers)
    return headers


def sign_headers(*args, **kwargs):
    """Alias of build_headers for convenience."""
    return build_headers(*args, **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
# Lita API Client
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # signing functions
    "SECRET_KEY",
    "generate_header",
    "build_headers",
    "sign_headers",
    "make_nonce",
    "make_trace_id",
    "now_ms",
    "API_HOST",
    "API_SCHEME",
    # client
    "LitaClient",
    "LitaAPIError",
    "ACCESS_TOKEN",
    "USER_ID",
    "APP_VERSION",
    "SOURCE_NAME",
    # endpoint functions
    "h5_init",
    "get_game_panel",
    "diamond_jackpot_enter_game",
    "diamond_jackpot_round",
    "diamond_jackpot_current_lottery",
    "diamond_jackpot_lottery_result",
    "diamond_jackpot_user_wager",
    "lottery_items",
    "user_account",
    "user_profile_basic",
    # session helpers
    "init",
    "get_client",
]

# ---------------------------------------------------------------------------
# Defaults dari capture yang sudah diverifikasi (user 24821290)
# ---------------------------------------------------------------------------
ACCESS_TOKEN = "UGvxft+Z/BctCVx4Sl5axccMOr8KoMPZf7635t5Xg7uGnq63FcxjZ5QFi1mEwwzb"
USER_ID = "24821290"
APP_VERSION = "1.326"
SOURCE_NAME = "MST"
GENDER = "0"

# Semua endpoint GET ini sudah diuji HTTP 200.
ENDPOINTS = {
    "h5_init": "/h5/init",
    "game_panel": "/active/wagerActive/getGamePanel",
    "dj_enter": "/active/v1.1/diamondJackpot/enterGame",
    "dj_round": "/active/v1.1/diamondJackpot/round",
    "dj_current": "/active/v1.1/diamondJackpot/currentlottery",
    "dj_result": "/active/v1.1/diamondJackpot/lotteryResultResp",
    "dj_wager": "/active/v1.1/diamondJackpot/userWagerResp",
    "lottery_items": "/funbit/v2/lottery/items",
    "user_account": "/funbit/v2/api/user/account",
    "user_profile": "/funbit/v2/api/user/profile/basic",
    # POST endpoints
    "dj_wager_post": "/active/v1.1/diamondJackpot/wager",
    "dj_wager_batch": "/active/v1.1/diamondJackpot/wagerBatch",
    "dj_amount": "/active/v2/diamondJackpot/getAmountV2",
}

# Item valid per tipe (dari turnplates enterGame).
VEGGIE_ITEMS = ("maize", "gree_pepper", "cabbage", "carrot")
FRUITS_ITEMS = ("coco", "watermelon", "mango", "durian")

# Nominal taruhan yang didukung server.
WAGER_AMOUNTS = (5, 10, 100, 1000)
WAGER_AMOUNT_MAX = 50000


class LitaAPIError(Exception):
    """Dilempar saat server membalas status non-200."""

    def __init__(self, status, path, payload):
        self.status = status
        self.path = path
        self.payload = payload
        super().__init__("HTTP %s on %s" % (status, path))


class LitaClient:
    """Client signed untuk h-api.lita.game."""

    def __init__(
        self,
        access_token=ACCESS_TOKEN,
        user_token="",
        user_id=USER_ID,
        app_version=APP_VERSION,
        source_name=SOURCE_NAME,
        gender=GENDER,
        locale="id-ID",
        platform="3",
        app_id="Lita",
        host=API_HOST,
        scheme=API_SCHEME,
        timeout=20,
        raise_on_error=True,
    ):
        self.access_token = access_token or ""
        self.user_token = user_token or ""
        self.user_id = str(user_id)
        self.app_version = str(app_version)
        self.source_name = str(source_name)
        self.gender = str(gender)
        self.locale = locale
        self.platform = platform
        self.app_id = app_id
        self.host = host
        self.scheme = scheme
        self.timeout = timeout
        self.raise_on_error = raise_on_error
        self.last_headers = {}
        self.last_status = None

    # ---------------------------------------------------------------- helpers
    def _extra_headers(self):
        extra = {
            "user-id": self.user_id,
            "gender": self.gender,
            "appVersion": self.app_version,
            "sourceName": self.source_name,
        }
        if self.access_token:
            extra["AccessToken"] = self.access_token
        return extra

    def request(self, path, method="GET", body=None, params=None, expected=(200,)):
        """Kirim request bertanda tangan. Mengembalikan (status, payload)."""
        if params:
            path = path + ("&" if "?" in path else "?") + urllib.parse.urlencode(params)

        if isinstance(body, (dict, list)):
            body_text = json.dumps(body, separators=(",", ":"))
        else:
            body_text = body or ""

        headers = build_headers(
            path=path,
            timestamp=now_ms(),
            nonce=make_nonce(),
            trace_id=make_trace_id(),
            locale=self.locale,
            platform=self.platform,
            app_id=self.app_id,
            user_token=self.user_token,
            access_token=self.access_token,
            body=body_text,
            extra_headers=self._extra_headers(),
        )
        self.last_headers = headers

        data = body_text.encode("utf-8") if body_text else None
        url = "%s://%s%s" % (self.scheme, self.host, path)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        self.last_status = status

        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text

        if expected and status not in expected and self.raise_on_error:
            raise LitaAPIError(status, path, payload)
        return status, payload

    def _get(self, path, params=None):
        status, payload = self.request(path, "GET", params=params)
        return payload

    def _post(self, path, body=None):
        status, payload = self.request(path, "POST", body=body)
        return payload

    # -------------------------------------------------------------- endpoints
    def h5_init(self):
        """GET /h5/init -- bootstrap token. Tidak pakai token di signature."""
        save_ut, save_at = self.user_token, self.access_token
        self.user_token, self.access_token = "", ""
        try:
            data = self._get(ENDPOINTS["h5_init"])
        finally:
            self.user_token, self.access_token = save_ut, save_at
        if isinstance(data, dict) and data.get("token"):
            self.user_token = data["token"]
        return data

    def init(self):
        """Alias eksplisit: bootstrap l-user-token dari /h5/init."""
        return self.h5_init()

    def get_game_panel(self):
        """GET /active/wagerActive/getGamePanel -- panel game aktif."""
        return self._get(ENDPOINTS["game_panel"])

    def diamond_jackpot_enter_game(self):
        """GET /active/v1.1/diamondJackpot/enterGame -- info ronde + piring."""
        return self._get(ENDPOINTS["dj_enter"])

    def diamond_jackpot_round(self):
        """GET /active/v1.1/diamondJackpot/round -- ronde saat ini."""
        return self._get(ENDPOINTS["dj_round"])

    def diamond_jackpot_current_lottery(self):
        """GET /active/v1.1/diamondJackpot/currentlottery -- status undian."""
        return self._get(ENDPOINTS["dj_current"])

    def diamond_jackpot_lottery_result(self):
        """GET /active/v1.1/diamondJackpot/lotteryResultResp -- riwayat hasil."""
        return self._get(ENDPOINTS["dj_result"])

    def diamond_jackpot_user_wager(self):
        """GET /active/v1.1/diamondJackpot/userWagerResp -- taruhan user."""
        return self._get(ENDPOINTS["dj_wager"])

    # ------------------------------------------------------------------ wager
    @staticmethod
    def build_wager_body(round_id, item_type, item_name, amount):
        """Bentuk body POST /wager."""
        return {
            "round": str(round_id),
            "itemType": str(item_type),
            "itemName": str(item_name),
            "amount": int(amount),
        }

    @staticmethod
    def validate_wager(item_type, item_name, amount):
        """Validasi ringan sebelum mengirim. Mengembalikan list pesan error."""
        errors = []
        if item_type == "veggie" and item_name not in VEGGIE_ITEMS:
            errors.append("itemName %r bukan veggie valid %s" % (item_name, list(VEGGIE_ITEMS)))
        if item_type == "fruits" and item_name not in FRUITS_ITEMS:
            errors.append("itemName %r bukan fruits valid %s" % (item_name, list(FRUITS_ITEMS)))
        if item_type not in ("veggie", "fruits"):
            errors.append("itemType harus 'veggie' atau 'fruits', bukan %r" % item_type)
        try:
            amt = int(amount)
            if amt <= 0:
                errors.append("amount harus > 0")
            elif amt > WAGER_AMOUNT_MAX:
                errors.append("amount %d > maksimum %d" % (amt, WAGER_AMOUNT_MAX))
            elif amt not in WAGER_AMOUNTS:
                errors.append("amount %d tidak ada di wagerAmountList %s" % (amt, list(WAGER_AMOUNTS)))
        except (TypeError, ValueError):
            errors.append("amount harus angka, bukan %r" % (amount,))
        return errors

    def diamond_jackpot_wager(self, round_id, item_type, item_name, amount, dry_run=False):
        """POST /active/v1.1/diamondJackpot/wager -- pasang taruhan."""
        body = self.build_wager_body(round_id, item_type, item_name, amount)
        errors = self.validate_wager(item_type, item_name, amount)
        if errors:
            raise ValueError("; ".join(errors))
        if dry_run:
            headers = build_headers(
                path=ENDPOINTS["dj_wager_post"],
                timestamp=now_ms(),
                nonce=make_nonce(),
                trace_id=make_trace_id(),
                locale=self.locale,
                platform=self.platform,
                app_id=self.app_id,
                user_token=self.user_token,
                access_token=self.access_token,
                body=json.dumps(body, separators=(",", ":")),
                extra_headers=self._extra_headers(),
            )
            return {
                "dry_run": True,
                "path": ENDPOINTS["dj_wager_post"],
                "body": body,
                "body_text": json.dumps(body, separators=(",", ":")),
                "headers": headers,
            }
        return self._post(ENDPOINTS["dj_wager_post"], body)

    def diamond_jackpot_wager_batch(self, items, round_id=None, dry_run=False):
        """POST /active/v1.1/diamondJackpot/wagerBatch -- beberapa taruhan sekaligus."""
        wagers = []
        for it in items:
            if isinstance(it, dict):
                rnd = it.get("round", round_id)
                wagers.append(self.build_wager_body(
                    rnd, it["itemType"], it["itemName"], it["amount"]))
            else:
                itype, iname, amt = it
                wagers.append(self.build_wager_body(round_id, itype, iname, amt))
        if dry_run:
            body_text = json.dumps(wagers, separators=(",", ":"))
            headers = build_headers(
                path=ENDPOINTS["dj_wager_batch"],
                timestamp=now_ms(),
                nonce=make_nonce(),
                trace_id=make_trace_id(),
                locale=self.locale,
                platform=self.platform,
                app_id=self.app_id,
                user_token=self.user_token,
                access_token=self.access_token,
                body=body_text,
                extra_headers=self._extra_headers(),
            )
            return {
                "dry_run": True,
                "path": ENDPOINTS["dj_wager_batch"],
                "body": wagers,
                "body_text": body_text,
                "headers": headers,
            }
        return self._post(ENDPOINTS["dj_wager_batch"], wagers)

    def diamond_jackpot_get_amount(self, body=None):
        """POST /active/v2/diamondJackpot/getAmountV2 -- batas & info nominal."""
        return self._post(ENDPOINTS["dj_amount"], body if body is not None else {})

    def lottery_items(self):
        """GET /funbit/v2/lottery/items -- daftar hadiah undian."""
        return self._get(ENDPOINTS["lottery_items"])

    def user_account(self):
        """GET /funbit/v2/api/user/account -- saldo & info penarikan."""
        return self._get(ENDPOINTS["user_account"])

    def user_profile_basic(self):
        """GET /funbit/v2/api/user/profile/basic -- profil dasar user."""
        return self._get(ENDPOINTS["user_profile"])

    def get_all(self):
        """Panggil semua 10 endpoint. Mengembalikan dict path->payload."""
        out = {}
        for name, path in ENDPOINTS.items():
            try:
                out[name] = self._get(path)
            except LitaAPIError as exc:
                out[name] = {"error": str(exc), "payload": exc.payload}
        return out


# ---------------------------------------------------------------------------
# Modul-level singleton + fungsi tanpa class
# ---------------------------------------------------------------------------
_default_client = None


def get_client(reset=False, **kwargs):
    """Ambil (atau buat) client default. `reset=True` untuk membuat ulang."""
    global _default_client
    if _default_client is None or reset:
        _default_client = LitaClient(**kwargs)
    return _default_client


def init(**kwargs):
    """Bootstrap token default lalu kembalikan client-nya."""
    client = get_client(**kwargs)
    client.init()
    return client


def _call(name, auto_init=True, **kwargs):
    client = get_client(**kwargs)
    if auto_init and not client.user_token:
        client.init()
    return getattr(client, name)()


def h5_init(**kwargs):
    return get_client(**kwargs).h5_init()


def get_game_panel(**kwargs):
    return _call("get_game_panel", **kwargs)


def diamond_jackpot_enter_game(**kwargs):
    return _call("diamond_jackpot_enter_game", **kwargs)


def diamond_jackpot_round(**kwargs):
    return _call("diamond_jackpot_round", **kwargs)


def diamond_jackpot_current_lottery(**kwargs):
    return _call("diamond_jackpot_current_lottery", **kwargs)


def diamond_jackpot_lottery_result(**kwargs):
    return _call("diamond_jackpot_lottery_result", **kwargs)


def diamond_jackpot_user_wager(**kwargs):
    return _call("diamond_jackpot_user_wager", **kwargs)


def lottery_items(**kwargs):
    return _call("lottery_items", **kwargs)


def user_account(**kwargs):
    return _call("user_account", **kwargs)


def user_profile_basic(**kwargs):
    return _call("user_profile_basic", **kwargs)


def diamond_jackpot_wager(round_id, item_type, item_name, amount, **kwargs):
    """POST wager. PENTING: mengurangi saldo. Pakai dry_run=True untuk preview."""
    client = get_client(**kwargs)
    if not client.user_token:
        client.init()
    return client.diamond_jackpot_wager(round_id, item_type, item_name, amount, **kwargs)


def diamond_jackpot_wager_batch(items, round_id=None, **kwargs):
    """POST wagerBatch. PENTING: mengurangi saldo. Pakai dry_run=True untuk preview."""
    client = get_client(**kwargs)
    if not client.user_token:
        client.init()
    return client.diamond_jackpot_wager_batch(items, round_id=round_id, **kwargs)


def diamond_jackpot_get_amount(**kwargs):
    return _call("diamond_jackpot_get_amount", **kwargs)


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Self-test signing
    print("=== litasignv self test ===")
    REFERENCE = {
        "path": "/h5/init",
        "timestamp": "1789133602964",
        "nonce": "d86Go65noUlOTwRr",
        "trace_id": "d68404721b0f3a3b24b75bf02ae3fabd",
        "locale": "id-ID",
        "platform": "3",
        "app_id": "Lita",
        "expected": "082bd3f2b573213",
    }
    _fields = _build_field_map(
        timestamp=REFERENCE["timestamp"],
        nonce=REFERENCE["nonce"],
        trace_id=REFERENCE["trace_id"],
        locale=REFERENCE["locale"],
        platform=REFERENCE["platform"],
        app_id=REFERENCE["app_id"],
    )
    _material = sign_material(REFERENCE["path"], _fields, "")
    _digest = hashlib.md5(_material.encode("utf-8")).hexdigest()
    _sign = _digest[3:18]
    print("l-sign      :", _sign)
    print("expected    :", REFERENCE["expected"])
    print("RESULT      :", "MATCH" if _sign == REFERENCE["expected"] else "MISMATCH")
    print()

    # API test
    print("=== lita_api.py test -- 10 endpoint h-api.lita.game ===\n")
    client = LitaClient()

    init_data = client.h5_init()
    print("[init] token = %s..." % (client.user_token[:32]))
    print()

    checks = [
        ("getGamePanel", client.get_game_panel),
        ("diamondJackpot/enterGame", client.diamond_jackpot_enter_game),
        ("diamondJackpot/round", client.diamond_jackpot_round),
        ("diamondJackpot/currentlottery", client.diamond_jackpot_current_lottery),
        ("diamondJackpot/lotteryResultResp", client.diamond_jackpot_lottery_result),
        ("diamondJackpot/userWagerResp", client.diamond_jackpot_user_wager),
        ("funbit/lottery/items", client.lottery_items),
        ("funbit/user/account", client.user_account),
        ("funbit/user/profile/basic", client.user_profile_basic),
    ]

    ok = 0
    for label, fn in checks:
        try:
            data = fn()
            state = data.get("state") if isinstance(data, dict) else None
            status = data.get("status") if isinstance(data, dict) else None
            keys = list(data.keys())[:5] if isinstance(data, dict) else type(data).__name__
            print("%-38s HTTP %s state=%-4s status=%-3s keys=%s"
                  % (label, client.last_status, state, status, keys))
            ok += client.last_status == 200
        except Exception as exc:  # noqa: BLE001
            print("%-38s ERROR %s" % (label, exc))
    print("\nRESULT: %d/9 endpoint OK" % ok)
    sys.exit(0 if ok == 9 else 1)
