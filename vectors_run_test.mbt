///|
fn vec_bytes(hex_text : String) -> Bytes {
  if hex_text.length() == 0 {
    b""
  } else {
    hex(hex_text)
  }
}

///|
fn vec_key(case : VecCase) -> @cose.CoseKey {
  if case.kty == "oct" {
    @cose.CoseKey::Sym(@cose.SymKey::new(vec_bytes(case.k_hex)))
  } else if case.kty == "OKP" {
    let d = if case.d_hex.length() == 0 {
      None
    } else {
      Some(vec_bytes(case.d_hex))
    }
    @cose.CoseKey::Okp({
      ..@cose.OkpKey::ed25519(vec_bytes(case.x_hex), d),
      crv: case.crv,
    })
  } else {
    let y = if case.y_hex.length() == 0 {
      None
    } else {
      Some(vec_bytes(case.y_hex))
    }
    let d = if case.d_hex.length() == 0 {
      None
    } else {
      Some(vec_bytes(case.d_hex))
    }
    @cose.CoseKey::Ec2({
      ..@cose.Ec2Key::p256(vec_bytes(case.x_hex), y, d),
      crv: case.crv,
    })
  }
}

///|
fn vec_payload_text(payload : Bytes?) -> String {
  match payload {
    Some(bytes) => @utf8.decode_lossy(bytes)
    None => ""
  }
}

///|
fn vec_outcome(case : VecCase) -> String {
  let raw = vec_bytes(case.cbor_hex)
  let aad = vec_bytes(case.external_hex)
  let key = vec_key(case)
  try {
    match case.kind {
      "sign1" => {
        let msg = @cose.Sign1::decode(raw)
        msg.verify(aad, key)
        if vec_payload_text(msg.payload) != case.plaintext {
          abort("\{case.category}/\{case.name} payload mismatch")
        }
      }
      "sign" => {
        let msg = @cose.Sign::decode(raw)
        msg.verify_signer(0, aad, key)
        if vec_payload_text(msg.payload) != case.plaintext {
          abort("\{case.category}/\{case.name} payload mismatch")
        }
      }
      "mac0" => {
        let msg = @cose.Mac0::decode(raw)
        msg.verify(aad, key)
        if vec_payload_text(msg.payload) != case.plaintext {
          abort("\{case.category}/\{case.name} payload mismatch")
        }
      }
      "encrypt0" => {
        let msg = @cose.Encrypt0::decode(raw)
        let pt = msg.decrypt(aad, key)
        if @utf8.decode_lossy(pt) != case.plaintext {
          abort("\{case.category}/\{case.name} plaintext mismatch")
        }
      }
      _ => abort("unknown kind \{case.kind}")
    }
    "ok"
  } catch {
    _ => "err"
  }
}

///|
test "cose-wg examples for supported structures" {
  let cases = vec_cases()
  let mut ok = 0
  let mut err = 0
  let mut unsupported = 0
  let mut inconsistent = 0
  for i = 0; i < cases.length(); i = i + 1 {
    let case = cases[i]
    let got = vec_outcome(case)
    if case.expect == "ok" {
      if got != "ok" {
        abort("\{case.category}/\{case.name} should verify")
      }
      ok = ok + 1
    } else {
      if got != "err" {
        abort("\{case.category}/\{case.name} should be rejected")
      }
      if case.expect == "unsupported" {
        unsupported = unsupported + 1
      } else if case.expect == "inconsistent" {
        inconsistent = inconsistent + 1
      } else {
        err = err + 1
      }
    }
  }
  assert_eq(cases.length(), 60)
  assert_eq(ok, 18)
  assert_eq(err, 18)
  assert_eq(unsupported, 20)
  assert_eq(inconsistent, 4)
}
