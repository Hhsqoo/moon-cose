///|
test "protected EdDSA header matches cose-wg eddsa-sig-01" {
  let header : @cose.Header = {
    ..@cose.Header::with_alg(@cose.EdDSA),
    content_type: Some(@cose.ContentType::Int(0)),
  }
  let prot = @cose.Protected::from_header(header)
  assert_eq(@hex.encode(prot.raw), "a201270300")
}

///|
test "Sig_structure Signature1 matches eddsa-sig-01 ToBeSign" {
  let prot = hex("a201270300")
  let payload = @utf8.encode("This is the content.")
  let tbs = @cose.sig_structure("Signature1", prot, None, b"", payload)
  assert_eq(
    @hex.encode(tbs),
    "846a5369676e61747572653145a2012703004054546869732069732074686520636f6e74656e742e",
  )
}

///|
test "MAC_structure and Enc_structure match direct-key examples" {
  let mac = @cose.mac_structure(
    "MAC0",
    b"",
    b"",
    @utf8.encode("This is the content."),
  )
  assert_eq(
    @hex.encode(mac),
    "84644d414330404054546869732069732074686520636f6e74656e742e",
  )
  let aad = @cose.enc_structure("Encrypt0", b"", b"")
  assert_eq(@hex.encode(aad), "8368456e6372797074304040")
}

///|
test "empty protected bstr decodes as an empty header" {
  let prot = @cose.Protected::from_raw(b"")
  assert_eq(prot.raw.length(), 0)
  assert_true(prot.header.alg is None)
}

///|
test "duplicate header label is rejected" {
  let raw = hex("a201010101")
  ignore(@cose.Protected::from_raw(raw)) catch {
    @cose.BadStructure(_) => return
    err => abort("unexpected \{err}")
  }
  abort("duplicate label was accepted")
}

///|
test "unknown critical header is rejected" {
  let header : @cose.Header = {
    ..@cose.Header::empty(),
    crit: [@cose.Label::Int(99)],
    rest: [(@cose.Label::Int(99), @cbor.Integer(1L))],
  }
  header.check_crit() catch {
    @cose.BadStructure(_) => return
    err => abort("unexpected \{err}")
  }
  abort("unknown crit was accepted")
}
