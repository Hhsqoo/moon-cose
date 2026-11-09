///|
fn must_fail(run : () -> Unit raise @cose.CoseError) -> Unit {
  try {
    run()
    abort("expected an error")
  } catch {
    _ => ()
  }
}

///|
fn flip_at(bytes : Bytes, index : Int32) -> Bytes {
  let out = Array::make(bytes.length(), b'\x00')
  for i = 0; i < bytes.length(); i = i + 1 {
    out[i] = bytes[i]
  }
  let at = if index < 0 {
    0
  } else if index >= bytes.length() {
    bytes.length() - 1
  } else {
    index
  }
  out[at] = (out[at].to_int() ^ 0x01).to_byte()
  Bytes::from_array(out)
}

///|
fn next_u64(state : Array[UInt64]) -> UInt64 {
  let mut x = state[0]
  x = x ^ (x << 13)
  x = x ^ (x >> 7)
  x = x ^ (x << 17)
  state[0] = x
  x
}

///|
fn random_bytes(state : Array[UInt64], len : Int32) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = (next_u64(state) & 0xFFUL).to_int().to_byte()
  }
  Bytes::from_array(out)
}

///|
fn prefix(bytes : Bytes, len : Int32) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = bytes[i]
  }
  Bytes::from_array(out)
}

///|
fn eddsa_key() -> @cose.CoseKey {
  @cose.CoseKey::Okp(
    @cose.OkpKey::ed25519(
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      Some(
        hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      ),
    ),
  )
}

///|
fn sym_key() -> @cose.CoseKey {
  @cose.CoseKey::Sym(
    @cose.SymKey::new(
      hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
    ),
  )
}

///|
fn cek_key() -> @cose.CoseKey {
  @cose.CoseKey::Sym(@cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")))
}

///|
fn sample_sign1() -> @cose.Sign1 raise @cose.CoseError {
  @cose.Sign1::sign(
    @cose.Header::with_alg(@cose.EdDSA),
    @cose.Header::empty(),
    Some(@utf8.encode("payload")),
    b"",
    eddsa_key(),
  )
}

///|
fn sample_sign() -> @cose.Sign raise @cose.CoseError {
  @cose.Sign::sign(
    @cose.Header::empty(),
    @cose.Header::empty(),
    Some(@utf8.encode("payload")),
    [
      {
        protected_header: @cose.Header::with_alg(@cose.EdDSA),
        unprotected: @cose.Header::empty(),
        key: eddsa_key(),
      },
    ],
    b"",
  )
}

///|
fn sample_mac0() -> @cose.Mac0 raise @cose.CoseError {
  @cose.Mac0::mac(
    @cose.Header::with_alg(@cose.HMAC_256_256),
    @cose.Header::empty(),
    Some(@utf8.encode("payload")),
    b"",
    sym_key(),
  )
}

///|
fn sample_encrypt0() -> @cose.Encrypt0 raise @cose.CoseError {
  @cose.Encrypt0::encrypt(
    @cose.Header::with_alg(@cose.A128GCM),
    { ..@cose.Header::empty(), iv: Some(hex("02d1f7e6f26c43d4868d87ce")), },
    @utf8.encode("payload"),
    b"",
    cek_key(),
  )
}

///|
fn sample_encrypt() -> @cose.Encrypt raise @cose.CoseError {
  let key = @cose.CoseKey::Sym({
    ..@cose.SymKey::new(hex("00112233445566778899aabbccddeeff")),
    kid: Some(hex("01")),
    alg: Some(@cose.A128KW),
  })
  @cose.Encrypt::encrypt(
    @cose.Header::with_alg(@cose.A128GCM),
    { ..@cose.Header::empty(), iv: Some(hex("02d1f7e6f26c43d4868d87ce")), },
    @utf8.encode("payload"),
    b"",
    hex("849b57219dae48de646d07dbb533566e"),
    [
      {
        unprotected: {
          ..@cose.Header::with_alg(@cose.A128KW),
          kid: Some(hex("01")),
        },
        key,
      },
    ],
  )
}

///|
fn reject_bytes(bytes : Bytes) -> Unit {
  must_fail(() => ignore(@cose.Sign1::decode(bytes)))
  must_fail(() => ignore(@cose.Sign::decode(bytes)))
  must_fail(() => ignore(@cose.Mac0::decode(bytes)))
  must_fail(() => ignore(@cose.Mac::decode(bytes)))
  must_fail(() => ignore(@cose.Encrypt0::decode(bytes)))
  must_fail(() => ignore(@cose.Encrypt::decode(bytes)))
  must_fail(() => ignore(@cose.CoseKey::decode(bytes)))
}

///|
test "truncated, mistyped, and random CBOR is rejected" {
  let sign1 = sample_sign1().encode()
  let sign = sample_sign().encode()
  let mac0 = sample_mac0().encode()
  let enc0 = sample_encrypt0().encode()
  let enc = sample_encrypt().encode()
  let samples = [sign1, sign, mac0, enc0, enc]
  for i = 0; i < samples.length(); i = i + 1 {
    let raw = samples[i]
    let cuts = [0, 1, 2, raw.length() / 2, raw.length() - 1]
    for n = 0; n < cuts.length(); n = n + 1 {
      reject_bytes(prefix(raw, cuts[n]))
    }
    reject_bytes(flip_at(raw, 0))
  }
  reject_bytes(hex("01"))
  reject_bytes(hex("a0"))
  reject_bytes(hex("f6"))
  reject_bytes(b"")
  let state : Array[UInt64] = [0xC0FFEEUL]
  for i = 0; i < 24; i = i + 1 {
    let len = (next_u64(state) % 48UL).to_int()
    ignore(i)
    reject_bytes(random_bytes(state, len))
  }
}

///|
test "flipping payload, protected header, or authenticator fails closed" {
  let sign1 = sample_sign1()
  let bad_payload : @cose.Sign1 = {
    ..sign1,
    payload: Some(@utf8.encode("other")),
  }
  must_fail(() => bad_payload.verify(b"", eddsa_key()))
  let bad_sig : @cose.Sign1 = {
    ..sign1,
    signature: flip_at(sign1.signature, 0),
  }
  must_fail(() => bad_sig.verify(b"", eddsa_key()))
  let bad_prot : @cose.Sign1 = {
    ..sign1,
    protected_header: @cose.Protected::from_raw(hex("a10126")),
  }
  must_fail(() => bad_prot.verify(b"", eddsa_key()))
  let signed = sample_sign()
  let bad_signer : @cose.Sign = {
    ..signed,
    signatures: [
      {
        ..signed.signatures[0],
        signature: flip_at(signed.signatures[0].signature, 3),
      },
    ],
  }
  must_fail(() => bad_signer.verify_signer(0, b"", eddsa_key()))
  let mac0 = sample_mac0()
  let bad_tag : @cose.Mac0 = { ..mac0, tag: flip_at(mac0.tag, 1), }
  must_fail(() => bad_tag.verify(b"", sym_key()))
  let enc0 = sample_encrypt0()
  match enc0.ciphertext {
    Some(ct) => {
      let bad : @cose.Encrypt0 = {
        ..enc0,
        ciphertext: Some(flip_at(ct, ct.length() - 1)),
      }
      must_fail(() => ignore(bad.decrypt(b"", cek_key())))
    }
    None => abort("missing ciphertext")
  }
  let enc = sample_encrypt()
  let kek = @cose.CoseKey::Sym({
    ..@cose.SymKey::new(hex("00112233445566778899aabbccddeeff")),
    kid: Some(hex("01")),
    alg: Some(@cose.A128KW),
  })
  match enc.ciphertext {
    Some(ct) => {
      let bad : @cose.Encrypt = { ..enc, ciphertext: Some(flip_at(ct, 0)), }
      must_fail(() => ignore(bad.decrypt(b"", kek)))
    }
    None => abort("missing ciphertext")
  }
  let wrapped = match enc.recipients[0].ciphertext {
    Some(value) => value
    None => abort("missing wrapped key")
  }
  let bad_wrap : @cose.Encrypt = {
    ..enc,
    recipients: [
      { ..enc.recipients[0], ciphertext: Some(flip_at(wrapped, 0)), },
    ],
  }
  must_fail(() => ignore(bad_wrap.decrypt(b"", kek)))
}
