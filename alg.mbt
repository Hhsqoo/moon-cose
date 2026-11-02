///|
/// COSE algorithm identifier. Known algorithms use their RFC 9053 integer
/// values on the wire (`ES256` = -7, `EdDSA` = -8, `HMAC_256_256` = 5,
/// `A128GCM` = 1, `A256GCM` = 3). Text names are accepted on decode.
pub(all) enum CoseAlg {
  ES256
  EdDSA
  HMAC_256_256
  A128GCM
  A256GCM
  Int(Int32)
  Text(String)
} derive(Eq, Debug)

///|
pub extend CoseAlg with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend CoseAlg with Eq::{not_equal}

///|
pub fn CoseAlg::normalize(self : CoseAlg) -> CoseAlg {
  match self {
    CoseAlg::Int(-7) | CoseAlg::Text("ES256") => CoseAlg::ES256
    CoseAlg::Int(-8) | CoseAlg::Text("EdDSA") => CoseAlg::EdDSA
    CoseAlg::Int(5) | CoseAlg::Text("HS256") => CoseAlg::HMAC_256_256
    CoseAlg::Int(1) | CoseAlg::Text("A128GCM") => CoseAlg::A128GCM
    CoseAlg::Int(3) | CoseAlg::Text("A256GCM") => CoseAlg::A256GCM
    other => other
  }
}

///|
pub fn CoseAlg::to_cbor(self : CoseAlg) -> @cbor.CborValue {
  match self.normalize() {
    CoseAlg::ES256 => @cbor.Integer(-7L)
    CoseAlg::EdDSA => @cbor.Integer(-8L)
    CoseAlg::HMAC_256_256 => @cbor.Integer(5L)
    CoseAlg::A128GCM => @cbor.Integer(1L)
    CoseAlg::A256GCM => @cbor.Integer(3L)
    CoseAlg::Int(n) => @cbor.Integer(n.to_int64())
    CoseAlg::Text(s) => @cbor.Text(s)
  }
}

///|
pub fn CoseAlg::from_cbor(value : @cbor.CborValue) -> CoseAlg raise CoseError {
  match value {
    @cbor.Integer(n) => CoseAlg::Int(int_from_i64(n)).normalize()
    @cbor.Unsigned(n) =>
      if n > 2147483647UL {
        raise BadStructure("algorithm integer is too large")
      } else {
        CoseAlg::Int(n.to_int()).normalize()
      }
    @cbor.Text(s) => CoseAlg::Text(s).normalize()
    _ => raise BadStructure("algorithm must be an int or a text string")
  }
}

///|
pub fn CoseAlg::name(self : CoseAlg) -> String {
  match self.normalize() {
    CoseAlg::ES256 => "ES256"
    CoseAlg::EdDSA => "EdDSA"
    CoseAlg::HMAC_256_256 => "HS256"
    CoseAlg::A128GCM => "A128GCM"
    CoseAlg::A256GCM => "A256GCM"
    CoseAlg::Int(n) => "int(\{n})"
    CoseAlg::Text(s) => s
  }
}

///|
/// Header map label: a CBOR int or text string (RFC 9052).
pub(all) enum Label {
  Int(Int32)
  Text(String)
} derive(Eq, Debug)

///|
pub extend Label with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Label with Eq::{not_equal}

///|
pub fn Label::to_cbor(self : Label) -> @cbor.CborValue {
  match self {
    Label::Int(n) => @cbor.Integer(n.to_int64())
    Label::Text(s) => @cbor.Text(s)
  }
}

///|
pub fn Label::from_cbor(value : @cbor.CborValue) -> Label raise CoseError {
  match value {
    @cbor.Integer(n) => Label::Int(int_from_i64(n))
    @cbor.Unsigned(n) =>
      if n > 2147483647UL {
        raise BadStructure("header label integer is too large")
      } else {
        Label::Int(n.to_int())
      }
    @cbor.Text(s) => Label::Text(s)
    _ => raise BadStructure("header label must be an int or a text string")
  }
}

///|
fn label_is_known(label : Label) -> Bool {
  match label {
    Label::Int(n) => n >= 1 && n <= 6
    Label::Text(_) => false
  }
}

///|
/// Content type header (`label` 3): an integer or a text media type.
pub(all) enum ContentType {
  Int(Int32)
  Text(String)
} derive(Eq, Debug)

///|
pub extend ContentType with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend ContentType with Eq::{not_equal}

///|
fn ContentType::to_cbor(self : ContentType) -> @cbor.CborValue {
  match self {
    ContentType::Int(n) => @cbor.Integer(n.to_int64())
    ContentType::Text(s) => @cbor.Text(s)
  }
}

///|
fn ContentType::from_cbor(
  value : @cbor.CborValue,
) -> ContentType raise CoseError {
  match value {
    @cbor.Integer(n) => ContentType::Int(int_from_i64(n))
    @cbor.Unsigned(n) =>
      if n > 2147483647UL {
        raise BadStructure("content type integer is too large")
      } else {
        ContentType::Int(n.to_int())
      }
    @cbor.Text(s) => ContentType::Text(s)
    _ => raise BadStructure("content type must be an int or a text string")
  }
}
