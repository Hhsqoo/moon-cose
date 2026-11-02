///|
/// One COSE header map (protected or unprotected).
///
/// `rest` keeps labels this library does not interpret, so a round trip can
/// preserve them. Critical labels in `crit` must be in the known set
/// (alg, crit, content type, kid, IV, partial IV).
pub(all) struct Header {
  alg : CoseAlg?
  crit : Array[Label]
  content_type : ContentType?
  kid : Bytes?
  iv : Bytes?
  partial_iv : Bytes?
  rest : Array[(Label, @cbor.CborValue)]
} derive(Eq)

///|
pub extend Header with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Header with Eq::{not_equal}

///|
pub fn Header::empty() -> Header {
  {
    alg: None,
    crit: [],
    content_type: None,
    kid: None,
    iv: None,
    partial_iv: None,
    rest: [],
  }
}

///|
pub fn Header::with_alg(alg : CoseAlg) -> Header {
  { ..Header::empty(), alg: Some(alg.normalize()), }
}

///|
pub fn Header::check_crit(self : Header) -> Unit raise CoseError {
  for i = 0; i < self.crit.length(); i = i + 1 {
    let label = self.crit[i]
    if !label_is_known(label) {
      raise BadStructure("critical header is not understood")
    }
  }
}

///|
fn expect_bytes(
  value : @cbor.CborValue,
  what : String,
) -> Bytes raise CoseError {
  match value {
    @cbor.Bytes(b) => b
    _ => raise BadStructure("\{what} must be a byte string")
  }
}

///|
fn seen_label(seen : Array[Label], label : Label) -> Bool {
  for i = 0; i < seen.length(); i = i + 1 {
    if seen[i] == label {
      return true
    }
  }
  false
}

///|
pub fn Header::from_cbor(value : @cbor.CborValue) -> Header raise CoseError {
  match value {
    @cbor.Map(pairs) => {
      let mut alg = None
      let mut crit = []
      let mut content_type = None
      let mut kid = None
      let mut iv = None
      let mut partial_iv = None
      let rest : Array[(Label, @cbor.CborValue)] = []
      let seen : Array[Label] = []
      for i = 0; i < pairs.length(); i = i + 1 {
        let label = Label::from_cbor(pairs[i].0)
        if seen_label(seen, label) {
          raise BadStructure("duplicate header label")
        }
        seen.push(label)
        let item = pairs[i].1
        match label {
          Label::Int(1) => alg = Some(CoseAlg::from_cbor(item))
          Label::Int(2) => crit = crit_from_cbor(item)
          Label::Int(3) => content_type = Some(ContentType::from_cbor(item))
          Label::Int(4) => kid = Some(expect_bytes(item, "kid"))
          Label::Int(5) => iv = Some(expect_bytes(item, "IV"))
          Label::Int(6) => partial_iv = Some(expect_bytes(item, "partial IV"))
          _ => rest.push((label, item))
        }
      }
      let header : Header = {
        alg,
        crit,
        content_type,
        kid,
        iv,
        partial_iv,
        rest,
      }
      header.check_crit()
      header
    }
    _ => raise BadStructure("header is not a map")
  }
}

///|
fn crit_from_cbor(value : @cbor.CborValue) -> Array[Label] raise CoseError {
  match value {
    @cbor.Array(items) => {
      if items.length() == 0 {
        raise BadStructure("crit array must not be empty")
      }
      let out : Array[Label] = []
      for i = 0; i < items.length(); i = i + 1 {
        out.push(Label::from_cbor(items[i]))
      }
      out
    }
    _ => raise BadStructure("crit must be an array of labels")
  }
}

///|
pub fn Header::to_cbor(self : Header) -> @cbor.CborValue {
  let pairs : Array[(@cbor.CborValue, @cbor.CborValue)] = []
  match self.alg {
    Some(alg) => pairs.push((@cbor.Integer(1L), alg.to_cbor()))
    None => ()
  }
  if self.crit.length() > 0 {
    let labels : Array[@cbor.CborValue] = []
    for i = 0; i < self.crit.length(); i = i + 1 {
      labels.push(self.crit[i].to_cbor())
    }
    pairs.push((@cbor.Integer(2L), @cbor.Array(labels)))
  }
  match self.content_type {
    Some(ct) => pairs.push((@cbor.Integer(3L), ct.to_cbor()))
    None => ()
  }
  match self.kid {
    Some(kid) => pairs.push((@cbor.Integer(4L), @cbor.Bytes(kid)))
    None => ()
  }
  match self.iv {
    Some(iv) => pairs.push((@cbor.Integer(5L), @cbor.Bytes(iv)))
    None => ()
  }
  match self.partial_iv {
    Some(piv) => pairs.push((@cbor.Integer(6L), @cbor.Bytes(piv)))
    None => ()
  }
  for i = 0; i < self.rest.length(); i = i + 1 {
    pairs.push((self.rest[i].0.to_cbor(), self.rest[i].1))
  }
  @cbor.Map(pairs)
}

///|
/// Encode this header map with deterministic CBOR (RFC 8949 section 4.2).
pub fn Header::encode(self : Header) -> Bytes {
  @cbor.encode(self.to_cbor())
}

///|
/// Protected header bucket: the raw `bstr` bytes are what Sig_structure,
/// MAC_structure, and Enc_structure commit to. An empty bstr is an empty map.
pub(all) struct Protected {
  raw : Bytes
  header : Header
} derive(Eq)

///|
pub extend Protected with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Protected with Eq::{not_equal}

///|
pub fn Protected::from_header(header : Header) -> Protected raise CoseError {
  header.check_crit()
  let encoded = header.encode()
  // RFC 9052 allows either `h''` or `h'a0'` for an empty header map.
  // Creation uses the zero-length form so it matches the cose-wg examples.
  if encoded.length() == 1 && encoded[0] == b'\xa0' {
    { raw: bytes_empty(), header, }
  } else {
    { raw: encoded, header, }
  }
}

///|
pub fn Protected::from_raw(raw : Bytes) -> Protected raise CoseError {
  if raw.length() == 0 {
    { raw, header: Header::empty(), }
  } else {
    let header = Header::from_cbor(decode_cbor(raw))
    { raw, header, }
  }
}

///|
pub fn resolve_alg(prot : Header, unprot : Header) -> CoseAlg raise CoseError {
  match (prot.alg, unprot.alg) {
    (Some(a), Some(b)) => {
      let left = a.normalize()
      let right = b.normalize()
      if left != right {
        raise AlgMismatch(
          "protected alg \{left.name()} does not match unprotected alg \{right.name()}",
        )
      }
      left
    }
    (Some(a), None) => a.normalize()
    (None, Some(b)) => b.normalize()
    (None, None) => raise BadStructure("missing alg header")
  }
}

///|
fn check_key_alg(
  key_alg : CoseAlg?,
  header_alg : CoseAlg,
) -> Unit raise CoseError {
  match key_alg {
    Some(alg) => {
      let key = alg.normalize()
      let header = header_alg.normalize()
      if key != header {
        raise AlgMismatch(
          "key alg \{key.name()} does not match header alg \{header.name()}",
        )
      }
    }
    None => ()
  }
}
