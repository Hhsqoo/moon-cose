///|
fn hx(text : String) -> Bytes {
  @hex.decode(text) catch {
    _ => abort("bad hex")
  }
}

///|
fn eddsa() -> @cose.CoseKey {
  @cose.CoseKey::Okp(
    @cose.OkpKey::ed25519(
      hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      Some(
        hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      ),
    ),
  )
}

///|
fn es256() -> @cose.CoseKey {
  @cose.CoseKey::Ec2(
    @cose.Ec2Key::p256(
      hx("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
      Some(
        hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
      ),
      Some(
        hx("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
      ),
    ),
  )
}

///|
fn main {
  try {
    let payload = @utf8.encode("release approved")
    let signed = @cose.Sign::sign(
      @cose.Header::empty(),
      @cose.Header::empty(),
      Some(payload),
      [
        {
          protected_header: @cose.Header::with_alg(@cose.EdDSA),
          unprotected: @cose.Header::empty(),
          key: eddsa(),
        },
        {
          protected_header: @cose.Header::with_alg(@cose.ES256),
          unprotected: @cose.Header::empty(),
          key: es256(),
        },
      ],
      b"",
    )
    let decoded = @cose.Sign::decode(signed.encode())
    decoded.verify_signer(0, b"", eddsa())
    decoded.verify_signer(1, b"", es256())
    println("multi-sign signers=\{decoded.signatures.length()}")
    println("multi-sign EdDSA verify ok")
    println("multi-sign ES256 verify ok")
  } catch {
    err => abort("multi-sign example failed: \{err}")
  }
}
