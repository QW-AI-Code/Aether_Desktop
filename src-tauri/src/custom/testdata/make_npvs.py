"""Independent NPVS v5 writer built from mobile NpvsCodec.kt (not from the Rust code).
Synthetic data only; the private key below is a throwaway test key."""
import hmac, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def mac(k, d): return hmac.new(k, d, hashlib.sha256).digest()
def hkdf(dek, salt, info): return mac(mac(salt, dek), info + b"\x01")
def seal(k, n, p, a): return ChaCha20Poly1305(k).encrypt(n, p, a)
u16 = lambda n: struct.pack(">H", n); u32 = lambda n: struct.pack(">I", n)

PASSWORD = "pw-سلام"
ITER = 1000
priv = ec.derive_private_key(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF, ec.SECP256R1())
creator = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
cid16 = bytes(range(16)); salt = bytes(range(32, 48)); wn = bytes(range(64, 76))
nonce = bytes(range(100, 112)); content = bytes(range(128, 160)); dek = bytes(range(200, 232))

kdk = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, ITER, 32)
wrap = wn + seal(kdk, wn, dek, salt)
assert len(wrap) == 60
prefix = b"\x01" + cid16 + creator + b"\x01" + u16(0) + u32(ITER) + salt + wrap
meta = json.dumps({"policy": {"attestationLevel": "NONE", "expiresAt": "", "onlyMobileNetwork": False,
                              "displayMessage": "پیام آزمایشی"}}, ensure_ascii=False).encode()
sealed_meta = seal(hkdf(dek, nonce, b"NPVS-v5/metadata"), nonce, meta, prefix)
header = prefix + u32(len(sealed_meta)) + sealed_meta
assert len(header) >= 135

fields = {
 1: '"سرور آزمایشی ۱"', 2: '"one.example.invalid"', 3: '5', 4: '"npvs1:NDQz"',
 5: '"11111111-2222-3333-4444-555555555555"', 6: '"tcp"', 7: '"none"',
 8: '"سرور آزمایشی ۲"', 9: '"two.example.invalid"', 10: '8443',
 65535: json.dumps({"configs": [
   {"name": 1, "v2rayProfile": {"server": 2, "configType": 3, "serverPort": 4, "password": 5, "network": 6, "security": 7}},
   {"name": 8, "v2rayProfile": {"server": 9, "configType": 3, "serverPort": 10, "password": 5, "network": 6, "security": 7}}]}),
}
body = b"NPF\x01" + content + u16(len(fields))
for seq, plain in fields.items():
    p = plain.encode()
    c = seal(hkdf(dek, content, b"NPV-fields-v1/field/" + u16(seq)), bytes(12), p,
             b"NPV-fields-v1/record/" + content + u16(seq) + u32(len(p)))
    body += u16(seq) + u16(0) + u16(len(c)) + c
body += bytes(32)
env = b"NPVS\x05" + u32(len(header)) + header + nonce + u32(len(body)) + body
r, s = decode_dss_signature(priv.sign(env, ec.ECDSA(hashes.SHA256())))
env += r.to_bytes(32, "big") + s.to_bytes(32, "big")
open(sys.argv[1], "wb").write(env); print(len(env), "bytes")
