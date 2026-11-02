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
    "hmac-examples",
    "encrypted-tests",
    "aes-gcm-examples",
]

SUPPORTED_ALGS = {-7, -8, 5, 1, 3}
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
    if "encrypted" in inp:
        return "encrypt0", inp["encrypted"]
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
    if isinstance(alg, int) and alg not in SUPPORTED_ALGS:
        return False
    if isinstance(alg, str) and alg not in ("ES256", "EdDSA", "HS256", "A128GCM", "A256GCM"):
        return False
    if alg in (-8, "EdDSA") and crv != "Ed25519":
        return False
    if alg in (-7, "ES256") and crv != "P-256":
        return False
    if alg in (1, "A128GCM") and len(k) != 32:
        return False
    if alg in (3, "A256GCM") and len(k) != 64:
        return False
    if alg in (5, "HS256") and kty != "oct":
        return False
    if kty == "OKP" and crv == "Ed25519" and len(x) != 64:
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
    if kind == "mac0":
        payload = arr[2][1] if arr[2][0] == "b" else b""
        tag = arr[3][1]
        tbs = bytes([0x84]) + tstr("MAC0") + bstr(prot) + bstr(aad) + bstr(payload)
        digest = hmac.new(bytes.fromhex(k), tbs, hashlib.sha256).digest()
        return digest == tag
    if kind == "encrypt0":
        unprot = arr[1][1]
        ct = arr[2][1] if arr[2][0] == "b" else b""
        iv_item = map_get(unprot, 5)
        if iv_item is None or iv_item[0] != "b":
            return False
        aad_bytes = bytes([0x83]) + tstr("Encrypt0") + bstr(prot) + bstr(aad)
        try:
            pt = AESGCM(bytes.fromhex(k)).decrypt(iv_item[1], ct, aad_bytes)
        except Exception:
            return False
        return pt == data["input"]["plaintext"].encode()
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
            if not supported(alg, key):
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
        for field in ("d_hex", "x_hex", "y_hex", "k_hex"):
            lines.append(f"      {field}: {moon_string(case[field])},")
        lines.append("    },")
    lines.append("  ]")
    lines.append("}")
    lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
