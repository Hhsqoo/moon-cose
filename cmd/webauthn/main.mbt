///|
fn hx(text : String) -> Bytes {
  @hex.decode(text) catch {
    _ => abort("bad hex")
  }
}

///|
fn public_es256() -> @cose.CoseKey {
  @cose.CoseKey::Ec2({
    ..@cose.Ec2Key::p256(
      hx("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
      Some(
        hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
      ),
      None,
    ),
    alg: Some(@cose.ES256),
  })
}

///|
fn signing_es256() -> @cose.CoseKey {
  @cose.CoseKey::Ec2({
    ..@cose.Ec2Key::p256(
      hx("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
      Some(
        hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
      ),
      Some(
        hx("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
      ),
    ),
    alg: Some(@cose.ES256),
  })
}

///|
fn public_eddsa() -> @cose.CoseKey {
  @cose.CoseKey::Okp({
    ..@cose.OkpKey::ed25519(
      hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      None,
    ),
    alg: Some(@cose.EdDSA),
  })
}

///|
fn signing_eddsa() -> @cose.CoseKey {
  @cose.CoseKey::Okp({
    ..@cose.OkpKey::ed25519(
      hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      Some(
        hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      ),
    ),
    alg: Some(@cose.EdDSA),
  })
}

///|
fn client_data() -> Bytes {
  @cbor.encode(
    @cbor.Map([
      (@cbor.Text("type"), @cbor.Text("webauthn.get")),
      (@cbor.Text("origin"), @cbor.Text("https://example.com")),
    ]),
  )
}

///|
fn check_one(
  name : String,
  alg : @cose.CoseAlg,
  stored : @cose.CoseKey,
  signer : @cose.CoseKey,
) -> Unit raise @cose.CoseError {
  let wire = stored.encode()
  let loaded = @cose.CoseKey::decode(wire)
  let signed = @cose.Sign1::sign(
    @cose.Header::with_alg(alg),
    @cose.Header::empty(),
    Some(client_data()),
    b"",
    signer,
  )
  @cose.Sign1::decode(signed.encode()).verify(b"", loaded)
  println("webauthn \{name} verify ok")
}

///|
fn main {
  try {
    check_one("ES256", @cose.ES256, public_es256(), signing_es256())
    check_one("EdDSA", @cose.EdDSA, public_eddsa(), signing_eddsa())
  } catch {
    err => abort("webauthn example failed: \{err}")
  }
}
