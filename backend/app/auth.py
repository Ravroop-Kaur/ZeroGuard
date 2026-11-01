"""Login primitives (stdlib only): scrypt passwords, RFC 6238 TOTP, HS256 tokens that reject any other algorithm."""
import base64, hashlib, hmac, json, os, struct, time


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def check_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32).hex()
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(calc, h)


def totp(secret_b32: str, t: float | None = None, step: int = 30) -> str:
    counter = int((time.time() if t is None else t) // step)
    h = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", counter), "sha1").digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


def totp_ok(secret_b32: str, code: str) -> bool:
    now = time.time()   # accept one step of clock drift either side
    return any(hmac.compare_digest(totp(secret_b32, now + d * 30), code) for d in (-1, 0, 1))


def new_totp_secret(seed: bytes, user_id: str) -> str:
    return base64.b32encode(hmac.new(seed, f"totp:{user_id}".encode(), "sha256").digest()[:10]).decode()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sig(secret: bytes, signing_input: str) -> str:
    return _b64(hmac.new(secret, signing_input.encode(), "sha256").digest())


def make_token(secret: bytes, claims: dict, ttl: int) -> str:
    now = int(time.time())
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay = _b64(json.dumps({**claims, "iat": now, "exp": now + ttl}).encode())
    return f"{head}.{pay}.{_sig(secret, head + '.' + pay)}"


def read_token(secret: bytes, token: str) -> dict | None:
    try:
        head, pay, sig = token.split(".")
        if json.loads(_unb64(head)).get("alg") != "HS256":
            return None
        if not hmac.compare_digest(sig, _sig(secret, head + "." + pay)):
            return None
        claims = json.loads(_unb64(pay))
        if not isinstance(claims.get("sub"), str) or claims.get("exp", 0) < time.time():
            return None
        return claims
    except Exception:
        return None
