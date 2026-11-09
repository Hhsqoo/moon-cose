///|
fn hx(text : String) -> Bytes {
  @hex.decode(text) catch {
    _ => abort("bad hex")
  }
}

///|
fn kek(name : String, material : String) -> @cose.CoseKey {
  @cose.CoseKey::Sym({
    ..@cose.SymKey::new(hx(material)),
    kid: Some(@utf8.encode(name)),
    alg: Some(@cose.A128KW),
  })
}

///|
fn recipient(key : @cose.CoseKey) -> @cose.RecipientInput {
  let kid = match key.kid() {
    Some(value) => value
    None => abort("recipient key has no kid")
  }
  {
    unprotected: { ..@cose.Header::with_alg(@cose.A128KW), kid: Some(kid), },
    key,
  }
}

///|
fn main {
  let alice = kek("alice", "00112233445566778899aabbccddeeff")
  let bob = kek("bob", "ffeeddccbbaa99887766554433221100")
  let cek = hx("849b57219dae48de646d07dbb533566e")
  let iv = hx("02d1f7e6f26c43d4868d87ce")
  try {
    let message = @cose.Encrypt::encrypt(
      @cose.Header::with_alg(@cose.A128GCM),
      { ..@cose.Header::empty(), iv: Some(iv), },
      @utf8.encode("rotate this credential"),
      b"",
      cek,
      [recipient(alice), recipient(bob)],
    )
    let encoded = message.encode()
    let opened = @cose.Encrypt::decode(encoded)
    let from_alice = opened.decrypt(b"", alice)
    let from_bob = opened.decrypt(b"", bob)
    if from_alice != from_bob ||
      @utf8.decode_lossy(from_alice) != "rotate this credential" {
      abort("recipient plaintext mismatch")
    }
    println(
      "encrypt recipients=\{message.recipients.length()} bytes=\{encoded.length()}",
    )
    println("encrypt alice decrypt ok")
    println("encrypt bob decrypt ok")
  } catch {
    err => abort("encrypt example failed: \{err}")
  }
}
