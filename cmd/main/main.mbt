///|
fn hx(text : String) -> Bytes {
  @hex.decode(text) catch {
    _ => abort("bad hex")
  }
}

///|
fn demo_sign1() -> Unit raise @cose.CoseError {
  let x = hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
  let d = hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  let key = @cose.CoseKey::Okp(@cose.OkpKey::ed25519(x, Some(d)))
  let payload = @cbor.encode(
    @cbor.Map([(@cbor.Text("hello"), @cbor.Text("moon-cose"))]),
  )
  let signed = @cose.Sign1::sign(
    @cose.Header::with_alg(@cose.EdDSA),
    @cose.Header::empty(),
    Some(payload),
    b"",
    key,
  )
  let encoded = signed.encode()
  let decoded = @cose.Sign1::decode(encoded)
  decoded.verify(b"", key)
  println("sign1 \{@hex.encode(encoded)}")
  println("sign1 verify ok")
}

///|
fn demo_mac0() -> Unit raise @cose.CoseError {
  let key = @cose.CoseKey::Sym(
    @cose.SymKey::new(hx("849b57219dae48de646d07dbb533566e")),
  )
  let payload = @utf8.encode("mac me")
  let mac = @cose.Mac0::mac(
    @cose.Header::with_alg(@cose.HMAC_256_256),
    @cose.Header::empty(),
    Some(payload),
    b"",
    key,
  )
  let decoded = @cose.Mac0::decode(mac.encode())
  decoded.verify(b"", key)
  println("mac0 \{@hex.encode(mac.encode())}")
  println("mac0 verify ok")
}

///|
fn demo_encrypt0() -> Unit raise @cose.CoseError {
  let key = @cose.CoseKey::Sym(
    @cose.SymKey::new(
      hx("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
    ),
  )
  let unprot : @cose.Header = {
    ..@cose.Header::empty(),
    iv: Some(hx("02d1f7e6f26c43d4868d87ce")),
  }
  let boxed = @cose.Encrypt0::encrypt(
    @cose.Header::with_alg(@cose.A256GCM),
    unprot,
    @utf8.encode("encrypt me"),
    b"external",
    key,
  )
  let opened = @cose.Encrypt0::decode(boxed.encode()).decrypt(b"external", key)
  if @utf8.decode_lossy(opened) != "encrypt me" {
    abort("encrypt0 round trip failed")
  }
  println("encrypt0 \{@hex.encode(boxed.encode())}")
  println("encrypt0 decrypt ok")
}

///|
fn main {
  try {
    demo_sign1()
    demo_mac0()
    demo_encrypt0()
  } catch {
    err => abort("demo failed: \{err}")
  }
}
