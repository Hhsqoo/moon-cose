///|
fn flip_last(b : Bytes) -> Bytes {
  let out = Array::make(b.length(), b'\x00')
  for i = 0; i < b.length(); i = i + 1 {
    out[i] = b[i]
  }
  let last = b.length() - 1
  out[last] = (out[last].to_int() ^ 0x01).to_byte()
  Bytes::from_array(out)
}

///|
fn ed25519_key() -> @cose.CoseKey {
  let x = hex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let d = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  @cose.CoseKey::Okp(@cose.OkpKey::ed25519(x, Some(d)))
}

///|
fn p256_key() -> @cose.CoseKey {
  @cose.CoseKey::Ec2(
    @cose.Ec2Key::p256(
      hex("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
      Some(
        hex("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
      ),
      Some(
        hex("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
      ),
    ),
  )
}

///|
fn expect_error(kind : String, run : () -> Unit raise @cose.CoseError) -> Unit {
  run() catch {
    err => {
      let got = match err {
        @cose.BadStructure(_) => "structure"
        @cose.UnsupportedAlg(_) => "unsupported"
        @cose.AlgMismatch(_) => "mismatch"
        @cose.VerificationFailed => "verify"
        @cose.DecryptionFailed => "decrypt"
        @cose.MalformedCbor(_) => "cbor"
      }
      if got != kind {
        abort("want \{kind} got \{got}: \{err}")
      }
      return
    }
  }
  abort("expected \{kind} error")
}

///|
test "COSE_Key round trip for OKP, EC2, and symmetric" {
  let okp = @cose.CoseKey::Okp({
    ..@cose.OkpKey::ed25519(
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      Some(
        hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      ),
    ),
    kid: Some(hex("3131")),
    alg: Some(@cose.EdDSA),
  })
  assert_true(@cose.CoseKey::decode(okp.encode()) == okp)
  let ec2 = p256_key()
  assert_true(@cose.CoseKey::decode(ec2.encode()) == ec2)
  let sym = @cose.CoseKey::Sym(
    @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
  )
  assert_true(@cose.CoseKey::decode(sym.encode()) == sym)
}

///|
test "Sign1 EdDSA reproduces eddsa-sig-01" {
  let payload = @utf8.encode("This is the content.")
  let protected_header : @cose.Header = {
    ..@cose.Header::with_alg(@cose.EdDSA),
    content_type: Some(@cose.ContentType::Int(0)),
  }
  let unprotected : @cose.Header = {
    ..@cose.Header::empty(),
    kid: Some(hex("3131")),
  }
  let msg = @cose.Sign1::sign(
    protected_header,
    unprotected,
    Some(payload),
    b"",
    ed25519_key(),
  )
  assert_eq(
    @hex.encode(msg.encode()),
    "d28445a201270300a10442313154546869732069732074686520636f6e74656e742e58407142fd2ff96d56db85bee905a76ba1d0b7321a95c8c4d3607c5781932b7afb8711497dfa751bf40b58b3bcc32300b1487f3db34085eef013bf08f4a44d6fef0d",
  )
  let decoded = @cose.Sign1::decode(msg.encode())
  decoded.verify(b"", ed25519_key())
}

///|
test "Sign1 ES256 verifies cose-wg sign-pass-02 and our own signature" {
  let message = @cose.Sign1::decode(
    hex(
      "d28443a10126a10442313154546869732069732074686520636f6e74656e742e584010729cd711cb3813d8d8e944a8da7111e7b258c9bdca6135f7ae1adbee9509891267837e1e33bd36c150326ae62755c6bd8e540c3e8f92d7d225e8db72b8820b",
    ),
  )
  let aad = hex("11aa22bb33cc44dd55006699")
  message.verify(aad, p256_key())
  let ours = @cose.Sign1::sign(
    @cose.Header::with_alg(@cose.ES256),
    @cose.Header::empty(),
    Some(@utf8.encode("This is the content.")),
    aad,
    p256_key(),
  )
  ours.verify(aad, p256_key())
  assert_true(bytes_eq_pub(ours.signature, message.signature))
}

///|
fn bytes_eq_pub(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
test "Sign1 tamper, alg mismatch, and malformed input" {
  let payload = @utf8.encode("This is the content.")
  let msg = @cose.Sign1::sign(
    @cose.Header::with_alg(@cose.EdDSA),
    @cose.Header::empty(),
    Some(payload),
    b"",
    ed25519_key(),
  )
  let bad_sig : @cose.Sign1 = { ..msg, signature: flip_last(msg.signature), }
  expect_error("verify", () => bad_sig.verify(b"", ed25519_key()))
  let bad_payload : @cose.Sign1 = {
    ..msg,
    payload: Some(@utf8.encode("tampered")),
  }
  expect_error("verify", () => bad_payload.verify(b"", ed25519_key()))
  let bad_prot : @cose.Sign1 = {
    ..msg,
    protected_header: @cose.Protected::from_raw(hex("a201270300")),
  }
  expect_error("verify", () => bad_prot.verify(b"", ed25519_key()))
  let mismatched = @cose.CoseKey::Okp({
    ..@cose.OkpKey::ed25519(
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      Some(
        hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      ),
    ),
    alg: Some(@cose.ES256),
  })
  expect_error("mismatch", () => {
    ignore(
      @cose.Sign1::sign(
        @cose.Header::with_alg(@cose.EdDSA),
        @cose.Header::empty(),
        Some(payload),
        b"",
        mismatched,
      ),
    )
  })
  expect_error("cbor", () => ignore(@cose.Sign1::decode(hex("ff"))))
  expect_error("structure", () => {
    ignore(
      @cose.Sign1::decode(
        hex(
          "d903e68443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
        ),
      ),
    )
  })
}

///|
test "COSE_Sign verifies eddsa-01 and a two-signer round trip" {
  let message = @cose.Sign::decode(
    hex(
      "d8628443a10300a054546869732069732074686520636f6e74656e742e818343a10127a104423131584077f3eacd11852c4bf9cb1d72fabe6b26fba1d76092b2b5b7ec83b83557652264e69690dbc1172ddc0bf88411c0d25a507fdb247a20c40d5e245fabd3fc9ec106",
    ),
  )
  message.verify_signer(0, b"", ed25519_key())
  let body : @cose.Header = {
    ..@cose.Header::empty(),
    content_type: Some(@cose.ContentType::Int(0)),
  }
  let signed = @cose.Sign::sign(
    body,
    @cose.Header::empty(),
    Some(@utf8.encode("hello")),
    [
      {
        protected_header: @cose.Header::with_alg(@cose.EdDSA),
        unprotected: @cose.Header::empty(),
        key: ed25519_key(),
      },
      {
        protected_header: @cose.Header::with_alg(@cose.ES256),
        unprotected: @cose.Header::empty(),
        key: p256_key(),
      },
    ],
    b"",
  )
  signed.verify_signer(0, b"", ed25519_key())
  signed.verify_signer(1, b"", p256_key())
  let again = @cose.Sign::decode(signed.encode())
  again.verify_signer(1, b"", p256_key())
}

///|
test "Mac0 HMAC-256 verifies external AAD and rejects a flipped tag" {
  let key = @cose.CoseKey::Sym(
    @cose.SymKey::new(
      hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
    ),
  )
  let aad = hex("ff00ee11dd22cc33bb44aa559966")
  let message = @cose.Mac0::decode(
    hex(
      "d18440a1010554546869732069732074686520636f6e74656e742e58200fecaec59bb46cc8a488aaca4b205e322dd52696b75a45768d3c302dd4bae2f7",
    ),
  )
  message.verify(aad, key)
  let bad : @cose.Mac0 = { ..message, tag: flip_last(message.tag), }
  expect_error("verify", () => bad.verify(aad, key))
  let prot = @cose.Header::with_alg(@cose.HMAC_256_256)
  let ours = @cose.Mac0::mac(
    prot,
    @cose.Header::empty(),
    Some(@utf8.encode("This is the content.")),
    b"",
    key,
  )
  ours.verify(b"", key)
  let bad_payload : @cose.Mac0 = {
    ..ours,
    payload: Some(@utf8.encode("other")),
  }
  expect_error("verify", () => bad_payload.verify(b"", key))
}

///|
test "Encrypt0 A128GCM decrypts enc-pass-02 and round trips A256GCM" {
  let key128 = @cose.CoseKey::Sym(
    @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
  )
  let aad = hex("0011bbcc22dd4455dd220099")
  let message = @cose.Encrypt0::decode(
    hex(
      "d08343a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb2898009ee52ecfd9ab1dd25867374b1dc3a143880ca2883a5630da08ae1e6e",
    ),
  )
  let pt = message.decrypt(aad, key128)
  assert_eq(@utf8.decode_lossy(pt), "This is the content.")
  let original = match message.ciphertext {
    Some(ct) => ct
    None => abort("missing ciphertext")
  }
  let bad : @cose.Encrypt0 = {
    ..message,
    ciphertext: Some(flip_last(original)),
  }
  expect_error("decrypt", () => ignore(bad.decrypt(aad, key128)))
  let key256 = @cose.CoseKey::Sym(
    @cose.SymKey::new(
      hex("0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100"),
    ),
  )
  let unprot : @cose.Header = {
    ..@cose.Header::empty(),
    iv: Some(hex("02d1f7e6f26c43d4868d87ce")),
  }
  let boxed = @cose.Encrypt0::encrypt(
    @cose.Header::with_alg(@cose.A256GCM),
    unprot,
    @utf8.encode("round trip"),
    b"",
    key256,
  )
  let opened = boxed.decrypt(b"", key256)
  assert_eq(@utf8.decode_lossy(opened), "round trip")
  let wrong : @cose.CoseKey = @cose.CoseKey::Sym({
    ..@cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
    alg: Some(@cose.A128GCM),
  })
  expect_error("mismatch", () => ignore(boxed.decrypt(b"", wrong)))
}
