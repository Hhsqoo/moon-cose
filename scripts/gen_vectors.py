#!/usr/bin/env python3
"""Extract cose-wg/Examples vectors into a MoonBit test table.

The examples are Unlicense. This script vendors the JSON files we execute and
writes vectors_gen.mbt. Expectations come from a spec-correct check: supported
algorithms must verify, failure vectors and inconsistent protected-header
examples must be rejected, and everything else must surface an error.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.environ.get("COSE_EXAMPLES", "/tmp/refs/cose-examples")
DEST = os.path.join(ROOT, "testdata", "cose-wg")

DIRS = [
    "sign1-tests",
    "sign-tests",
    "eddsa-examples",
    "ecdsa-examples",
    "mac0-tests",
    "mac-tests",
    "hmac-examples",
    "encrypted-tests",
    "enveloped-tests",
    "aes-gcm-examples",
    "aes-ccm-examples",
    "aes-wrap-examples",
    "chacha-poly-examples",
]

CONTENT_ALGS = {
    -7, -8, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 24, 30, 31, 32, 33,
    "ES256", "EdDSA", "HS256", "HS256/64", "HS384", "HS512",
    "A128GCM", "A192GCM", "A256GCM", "ChaCha-Poly1305", "ChaCha20/Poly1305",
    "AES-CCM-16-128/64", "AES-CCM-16-256/64", "AES-CCM-64-128/64", "AES-CCM-64-256/64",
    "AES-CCM-16-128/128", "AES-CCM-16-256/128", "AES-CCM-64-128/128", "AES-CCM-64-256/128",
}
RECIPIENT_ALGS = {-6, -3, -4, -5, "direct", "A128KW", "A192KW", "A256KW"}
CURVE = {"Ed25519": 6, "Ed448": 7, "P-256": 1, "P-384": 2, "P-521": 3}


def b64u(text):
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text)


def parse(data):
    i = 0

    def need(n):
        nonlocal i
        blob = data[i : i + n]
        i += n
        return blob

    def read_uint(ai):
        if ai < 24:
            return ai
        if ai == 24:
            return need(1)[0]
        if ai == 25:
            return int.from_bytes(need(2), "big")
        if ai == 26:
            return int.from_bytes(need(4), "big")
        if ai == 27:
            return int.from_bytes(need(8), "big")
        raise ValueError(ai)

    def read_item():
        byte = need(1)[0]
        major, ai = byte >> 5, byte & 31
        if major == 6:
            read_uint(ai)
            return read_item()
        if major == 2:
            return ("b", need(read_uint(ai)))
        if major == 3:
            return ("t", need(read_uint(ai)))
        if major == 4:
            n = read_uint(ai)
            return ("a", [read_item() for _ in range(n)])
        if major == 5:
            n = read_uint(ai)
            return ("m", [(read_item(), read_item()) for _ in range(n)])
        if major == 0:
            return ("u", read_uint(ai))
        if major == 1:
            return ("n", -1 - read_uint(ai))
        if major == 7 and ai == 22:
            return ("null", None)
        raise ValueError((major, ai))

    return read_item()


def bstr(blob):
    if len(blob) < 24:
        return bytes([0x40 + len(blob)]) + blob
    if len(blob) < 256:
        return bytes([0x58, len(blob)]) + blob
    return bytes([0x59]) + len(blob).to_bytes(2, "big") + blob


def tstr(text):
    blob = text.encode()
    if len(blob) < 24:
        return bytes([0x60 + len(blob)]) + blob
    return bytes([0x78, len(blob)]) + blob


def label_value(item):
    if item[0] == "u":
        return item[1]
    if item[0] == "n":
        return item[1]
    return None


def map_get(pairs, label):
    for key, value in pairs:
        if label_value(key) == label:
            return value
    return None


def alg_of(pairs):
    value = map_get(pairs, 1)
    if value is None:
        return None
    if value[0] in ("u", "n"):
        return value[1]
    if value[0] == "t":
        return value[1].decode()
    return None


def raw_to_der(sig):
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    def enc(num):
        blob = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
        if blob[0] & 0x80:
            blob = b"\x00" + blob
        return b"\x02" + bytes([len(blob)]) + blob

    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


def key_material(key):
    kty = key.get("kty", "")
    crv = key.get("crv", "")

    def field(name):
        hex_name = name + "_hex"
        if hex_name in key:
            return key[hex_name]
        if name in key and kty != "oct":
            return b64u(key[name]).hex()
        return ""

    k_hex = b64u(key["k"]).hex() if "k" in key else ""
    return kty, crv, field("d"), field("x"), field("y"), k_hex


def kind_of(data):
    inp = data["input"]
    if "sign0" in inp:
        return "sign1", inp["sign0"]
    if "sign" in inp:
        return "sign", inp["sign"]
    if "mac0" in inp:
        return "mac0", inp["mac0"]
    if "mac" in inp:
        return "mac", inp["mac"]
    if "encrypted" in inp:
        return "encrypt0", inp["encrypted"]
    if "enveloped" in inp:
        return "encrypt", inp["enveloped"]
    return None, None


def external_of(obj):
    if "external" in obj:
        return obj["external"]
    for signer in obj.get("signers", []):
        if "external" in signer:
            return signer["external"]
    return ""


def primary_key(obj, kind):
    if kind in ("sign1",):
        return obj["key"]
    if kind == "sign":
        return obj["signers"][0]["key"]
    return obj["recipients"][0]["key"]


def supported(alg, key):
    kty, crv, _d, x, _y, k = key
    if alg not in CONTENT_ALGS:
        return False
    if alg in (-8, "EdDSA") and crv != "Ed25519":
        return False
    if alg in (-7, "ES256") and crv != "P-256":
        return False
    if alg in (1, "A128GCM") and k and len(k) != 32:
        return False
    if alg in (2, "A192GCM") and k and len(k) != 48:
        return False
    if alg in (3, "A256GCM", 24, "ChaCha-Poly1305", "ChaCha20/Poly1305") and k and len(k) != 64:
        return False
    if alg in (4, 5, 6, 7, "HS256", "HS256/64", "HS384", "HS512") and kty != "oct":
        return False
    if kty == "OKP" and crv == "Ed25519" and len(x) != 64:
        return False
    return True


def supported_recipient(alg, key):
    _kty, _crv, _d, _x, _y, k = key
    if alg not in RECIPIENT_ALGS:
        return False
    if alg in (-3, "A128KW") and len(k) != 32:
        return False
    if alg in (-4, "A192KW") and len(k) != 48:
        return False
    if alg in (-5, "A256KW") and len(k) != 64:
        return False
    return True


def crypto_ok(kind, data, obj, key, aad, parsed):
    arr = parsed[1]
    prot = arr[0][1]
    kty, crv, d, x, y, k = key
    if kind == "sign1":
        payload = arr[2][1] if arr[2][0] == "b" else b""
        sig = arr[3][1]
        tbs = bytes([0x84]) + tstr("Signature1") + bstr(prot) + bstr(aad) + bstr(payload)
        return verify_sig(kty, crv, x, y, sig, tbs)
    if kind == "sign":
        payload = arr[2][1] if arr[2][0] == "b" else b""
        row = arr[3][1][0][1]
        sprot = row[0][1]
        sig = row[2][1]
        tbs = (
            bytes([0x85])
            + tstr("Signature")
            + bstr(prot)
            + bstr(sprot)
            + bstr(aad)
            + bstr(payload)
        )
        return verify_sig(kty, crv, x, y, sig, tbs)
    if kind in ("mac0", "mac"):
        payload = arr[2][1] if arr[2][0] == "b" else b""
        tag = arr[3][1]
        context = "MAC0" if kind == "mac0" else "MAC"
        tbs = bytes([0x84]) + tstr(context) + bstr(prot) + bstr(aad) + bstr(payload)
        digest = mac_digest(message_alg(kind, parsed), cek_bytes(data, k), tbs)
        return digest == tag
    if kind in ("encrypt0", "encrypt"):
        unprot = arr[1][1]
        ct = arr[2][1] if arr[2][0] == "b" else b""
        context = "Encrypt0" if kind == "encrypt0" else "Encrypt"
        iv = iv_bytes(data, obj, unprot)
        if iv is None:
            return False
        aad_bytes = bytes([0x83]) + tstr(context) + bstr(prot) + bstr(aad)
        return aead_open(
            message_alg(kind, parsed),
            cek_bytes(data, k),
            iv,
            aad_bytes,
            ct,
            data["input"]["plaintext"].encode(),
        )
    return False


def cek_bytes(data, k_hex):
    inter = data.get("intermediates") or {}
    if inter.get("CEK_hex"):
        return bytes.fromhex(inter["CEK_hex"])
    return bytes.fromhex(k_hex)


def iv_bytes(data, obj, unprot):
    item = map_get(unprot, 5)
    if item is not None and item[0] == "b":
        return item[1]
    unsent = (obj.get("unsent") or {}).get("IV_hex")
    if unsent:
        return bytes.fromhex(unsent)
    return None


def mac_digest(alg, key, tbs):
    if alg in (4, "HS256/64"):
        return hmac.new(key, tbs, hashlib.sha256).digest()[:8]
    if alg in (5, "HS256"):
        return hmac.new(key, tbs, hashlib.sha256).digest()
    if alg in (6, "HS384"):
        return hmac.new(key, tbs, hashlib.sha384).digest()
    if alg in (7, "HS512"):
        return hmac.new(key, tbs, hashlib.sha512).digest()
    return None


def aead_open(alg, key, iv, aad, ct, plaintext):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305

    try:
        if alg in (1, 2, 3, "A128GCM", "A192GCM", "A256GCM"):
            return AESGCM(key).decrypt(iv, ct, aad) == plaintext
        if alg in (24, "ChaCha-Poly1305", "ChaCha20/Poly1305"):
            return ChaCha20Poly1305(key).decrypt(iv, ct, aad) == plaintext
        tag_len = 8 if alg in (
            10, 11, 12, 13,
            "AES-CCM-16-128/64", "AES-CCM-16-256/64",
            "AES-CCM-64-128/64", "AES-CCM-64-256/64",
        ) else 16
        if alg in (
            10, 11, 12, 13, 30, 31, 32, 33,
            "AES-CCM-16-128/64", "AES-CCM-16-256/64",
            "AES-CCM-64-128/64", "AES-CCM-64-256/64",
            "AES-CCM-16-128/128", "AES-CCM-16-256/128",
            "AES-CCM-64-128/128", "AES-CCM-64-256/128",
        ):
            return AESCCM(key, tag_length=tag_len).decrypt(iv, ct, aad) == plaintext
    except Exception:
        return False
    return False


def verify_sig(kty, crv, x, y, sig, tbs):
    try:
        if kty == "OKP" and crv == "Ed25519":
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(x))
            pub.verify(sig, tbs)
            return True
        if kty == "EC" and crv == "P-256" and len(sig) == 64:
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(bytes.fromhex(x), "big"),
                int.from_bytes(bytes.fromhex(y), "big"),
                ec.SECP256R1(),
            ).public_key()
            pub.verify(raw_to_der(sig), tbs, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, Exception):
        return False
    return False


def recipient_alg(kind, parsed):
    if kind not in ("mac", "encrypt"):
        return -6
    index = 4 if kind == "mac" else 3
    row = parsed[1][index][1][0][1]
    prot = row[0][1]
    unprot = row[1][1]
    alg = alg_of(parse(prot)[1]) if prot else None
    if alg is None:
        alg = alg_of(unprot)
    return alg


def base_iv_hex(obj):
    unsent = (obj.get("unsent") or {}).get("IV_hex")
    partial = (obj.get("unprotected") or {}).get("partialIV_hex")
    if not unsent or not partial:
        return ""
    full = bytearray.fromhex(unsent)
    part = bytes.fromhex(partial)
    start = len(full) - len(part)
    for i, byte in enumerate(part):
        full[start + i] ^= byte
    return full.hex()


def message_alg(kind, parsed):
    arr = parsed[1]
    prot = arr[0][1]
    unprot = arr[1][1]
    header_alg = None
    if prot:
        header_alg = alg_of(parse(prot)[1])
    if header_alg is None:
        header_alg = alg_of(unprot)
    if kind == "sign":
        row = arr[3][1][0][1]
        signer_prot = row[0][1]
        signer_unprot = row[1][1]
        signer_alg = alg_of(parse(signer_prot)[1]) if signer_prot else None
        if signer_alg is None:
            signer_alg = alg_of(signer_unprot)
        return signer_alg
    return header_alg


def moon_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    if os.path.exists(DEST):
        shutil.rmtree(DEST)
    os.makedirs(DEST)
    cases = []
    for directory in DIRS:
        os.makedirs(os.path.join(DEST, directory), exist_ok=True)
        for name in sorted(os.listdir(os.path.join(SRC, directory))):
            if not name.endswith(".json"):
                continue
            src = os.path.join(SRC, directory, name)
            shutil.copy(src, os.path.join(DEST, directory, name))
            data = json.load(open(src))
            kind, obj = kind_of(data)
            if kind is None:
                continue
            key = key_material(primary_key(obj, kind))
            cbor = bytes.fromhex(data["output"]["cbor"])
            parsed = parse(cbor)
            alg = message_alg(kind, parsed)
            aad = bytes.fromhex(external_of(obj)) if external_of(obj) else b""
            if kind in ("mac", "encrypt"):
                usable = alg in CONTENT_ALGS and supported_recipient(
                    recipient_alg(kind, parsed), key
                )
            else:
                usable = supported(alg, key)
            if not usable:
                expect = "unsupported"
            elif data.get("fail"):
                expect = "err"
            elif crypto_ok(kind, data, obj, key, aad, parsed):
                expect = "ok"
            else:
                expect = "inconsistent"
            kty, crv, d, x, y, k = key
            crv_id = CURVE.get(crv, 0)
            cases.append(
                {
                    "category": directory,
                    "name": name[:-5],
                    "kind": kind,
                    "expect": expect,
                    "cbor_hex": data["output"]["cbor"].lower(),
                    "external_hex": aad.hex(),
                    "plaintext": data["input"]["plaintext"],
                    "kty": kty,
                    "crv": crv_id,
                    "d_hex": d,
                    "x_hex": x,
                    "y_hex": y,
                    "k_hex": k,
                    "base_iv_hex": base_iv_hex(obj),
                }
            )
    out = os.path.join(ROOT, "vectors_gen_test.mbt")
    with open(out, "w") as fh:
        fh.write(render(cases))
    counts = {}
    for case in cases:
        bucket = counts.setdefault(
            case["category"], {"ok": 0, "err": 0, "unsupported": 0, "inconsistent": 0}
        )
        bucket[case["expect"]] += 1
    print(json.dumps(counts, indent=2))
    print("cases", len(cases))


def render(cases):
    lines = [
        "///|",
        "/// Generated by scripts/gen_vectors.py from testdata/cose-wg.",
        "/// Do not edit by hand.",
        "struct VecCase {",
        "  category : String",
        "  name : String",
        "  kind : String",
        "  expect : String",
        "  cbor_hex : String",
        "  external_hex : String",
        "  plaintext : String",
        "  kty : String",
        "  crv : Int",
        "  d_hex : String",
        "  x_hex : String",
        "  y_hex : String",
        "  k_hex : String",
        "  base_iv_hex : String",
        "}",
        "",
        "///|",
        "fn vec_cases() -> Array[VecCase] {",
        "  [",
    ]
    for case in cases:
        lines.append("    {")
        for field in (
            "category",
            "name",
            "kind",
            "expect",
            "cbor_hex",
            "external_hex",
            "plaintext",
        ):
            lines.append(f"      {field}: {moon_string(case[field])},")
        lines.append(f"      kty: {moon_string(case['kty'])},")
        lines.append(f"      crv: {case['crv']},")
        for field in ("d_hex", "x_hex", "y_hex", "k_hex", "base_iv_hex"):
            lines.append(f"      {field}: {moon_string(case[field])},")
        lines.append("    },")
    lines.append("  ]")
    lines.append("}")
    lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
