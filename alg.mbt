///|
/// COSE algorithm identifier. Known algorithms use their RFC 9053 integer
/// values on the wire (`ES256` = -7, `EdDSA` = -8, `HMAC_256_256` = 5,
/// `A128GCM` = 1, `A256GCM` = 3). Text names are accepted on decode.
pub(all) enum CoseAlg {
  ES256
  EdDSA
  HMAC_256_64
  HMAC_256_256
  HMAC_384_384
  HMAC_512_512
  A128GCM
  A192GCM
  A256GCM
  ChaCha20Poly1305
  Direct
  A128KW
  A192KW
  A256KW
  AesCcm16_64_128
  AesCcm16_64_256
  AesCcm64_64_128
  AesCcm64_64_256
  AesCcm16_128_128
  AesCcm16_128_256
  AesCcm64_128_128
  AesCcm64_128_256
  Int(Int32)
  Text(String)
} derive(Eq)

///|
pub extend CoseAlg with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend CoseAlg with Eq::{not_equal}

///|
/// Map integer and text aliases onto the named algorithm variants.
pub fn CoseAlg::normalize(self : CoseAlg) -> CoseAlg {
  match self {
    CoseAlg::Int(-7) | CoseAlg::Text("ES256") => CoseAlg::ES256
    CoseAlg::Int(-8) | CoseAlg::Text("EdDSA") => CoseAlg::EdDSA
    CoseAlg::Int(4) | CoseAlg::Text("HS256/64") => CoseAlg::HMAC_256_64
    CoseAlg::Int(5) | CoseAlg::Text("HS256") => CoseAlg::HMAC_256_256
    CoseAlg::Int(6) | CoseAlg::Text("HS384") => CoseAlg::HMAC_384_384
    CoseAlg::Int(7) | CoseAlg::Text("HS512") => CoseAlg::HMAC_512_512
    CoseAlg::Int(1) | CoseAlg::Text("A128GCM") => CoseAlg::A128GCM
    CoseAlg::Int(2) | CoseAlg::Text("A192GCM") => CoseAlg::A192GCM
    CoseAlg::Int(3) | CoseAlg::Text("A256GCM") => CoseAlg::A256GCM
    CoseAlg::Int(24)
    | CoseAlg::Text("ChaCha20/Poly1305")
    | CoseAlg::Text("ChaCha-Poly1305") => CoseAlg::ChaCha20Poly1305
    CoseAlg::Int(-6) | CoseAlg::Text("direct") => CoseAlg::Direct
    CoseAlg::Int(-3) | CoseAlg::Text("A128KW") => CoseAlg::A128KW
    CoseAlg::Int(-4) | CoseAlg::Text("A192KW") => CoseAlg::A192KW
    CoseAlg::Int(-5) | CoseAlg::Text("A256KW") => CoseAlg::A256KW
    CoseAlg::Int(10)
    | CoseAlg::Text("AES-CCM-16-64-128")
    | CoseAlg::Text("AES-CCM-16-128/64") => CoseAlg::AesCcm16_64_128
    CoseAlg::Int(11)
    | CoseAlg::Text("AES-CCM-16-64-256")
    | CoseAlg::Text("AES-CCM-16-256/64") => CoseAlg::AesCcm16_64_256
    CoseAlg::Int(12)
    | CoseAlg::Text("AES-CCM-64-64-128")
    | CoseAlg::Text("AES-CCM-64-128/64") => CoseAlg::AesCcm64_64_128
    CoseAlg::Int(13)
    | CoseAlg::Text("AES-CCM-64-64-256")
    | CoseAlg::Text("AES-CCM-64-256/64") => CoseAlg::AesCcm64_64_256
    CoseAlg::Int(30)
    | CoseAlg::Text("AES-CCM-16-128-128")
    | CoseAlg::Text("AES-CCM-16-128/128") => CoseAlg::AesCcm16_128_128
    CoseAlg::Int(31)
    | CoseAlg::Text("AES-CCM-16-128-256")
    | CoseAlg::Text("AES-CCM-16-256/128") => CoseAlg::AesCcm16_128_256
    CoseAlg::Int(32)
    | CoseAlg::Text("AES-CCM-64-128-128")
    | CoseAlg::Text("AES-CCM-64-128/128") => CoseAlg::AesCcm64_128_128
    CoseAlg::Int(33)
    | CoseAlg::Text("AES-CCM-64-128-256")
    | CoseAlg::Text("AES-CCM-64-256/128") => CoseAlg::AesCcm64_128_256
    other => other
  }
}

///|
/// Encode the algorithm as its RFC 9053 integer, or as text if it has no integer form.
pub fn CoseAlg::to_cbor(self : CoseAlg) -> @cbor.CborValue {
  match self.normalize() {
    CoseAlg::ES256 => @cbor.Integer(-7L)
    CoseAlg::EdDSA => @cbor.Integer(-8L)
    CoseAlg::HMAC_256_64 => @cbor.Integer(4L)
    CoseAlg::HMAC_256_256 => @cbor.Integer(5L)
    CoseAlg::HMAC_384_384 => @cbor.Integer(6L)
    CoseAlg::HMAC_512_512 => @cbor.Integer(7L)
    CoseAlg::A128GCM => @cbor.Integer(1L)
    CoseAlg::A192GCM => @cbor.Integer(2L)
    CoseAlg::A256GCM => @cbor.Integer(3L)
    CoseAlg::ChaCha20Poly1305 => @cbor.Integer(24L)
    CoseAlg::Direct => @cbor.Integer(-6L)
    CoseAlg::A128KW => @cbor.Integer(-3L)
    CoseAlg::A192KW => @cbor.Integer(-4L)
    CoseAlg::A256KW => @cbor.Integer(-5L)
    CoseAlg::AesCcm16_64_128 => @cbor.Integer(10L)
    CoseAlg::AesCcm16_64_256 => @cbor.Integer(11L)
    CoseAlg::AesCcm64_64_128 => @cbor.Integer(12L)
    CoseAlg::AesCcm64_64_256 => @cbor.Integer(13L)
    CoseAlg::AesCcm16_128_128 => @cbor.Integer(30L)
    CoseAlg::AesCcm16_128_256 => @cbor.Integer(31L)
    CoseAlg::AesCcm64_128_128 => @cbor.Integer(32L)
    CoseAlg::AesCcm64_128_256 => @cbor.Integer(33L)
    CoseAlg::Int(n) => @cbor.Integer(n.to_int64())
    CoseAlg::Text(s) => @cbor.Text(s)
  }
}

///|
/// Read an algorithm from a CBOR int or text string.
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
/// Short name used in error messages.
pub fn CoseAlg::name(self : CoseAlg) -> String {
  match self.normalize() {
    CoseAlg::ES256 => "ES256"
    CoseAlg::EdDSA => "EdDSA"
    CoseAlg::HMAC_256_64 => "HS256/64"
    CoseAlg::HMAC_256_256 => "HS256"
    CoseAlg::HMAC_384_384 => "HS384"
    CoseAlg::HMAC_512_512 => "HS512"
    CoseAlg::A128GCM => "A128GCM"
    CoseAlg::A192GCM => "A192GCM"
    CoseAlg::A256GCM => "A256GCM"
    CoseAlg::ChaCha20Poly1305 => "ChaCha20/Poly1305"
    CoseAlg::Direct => "direct"
    CoseAlg::A128KW => "A128KW"
    CoseAlg::A192KW => "A192KW"
    CoseAlg::A256KW => "A256KW"
    CoseAlg::AesCcm16_64_128 => "AES-CCM-16-128/64"
    CoseAlg::AesCcm16_64_256 => "AES-CCM-16-256/64"
    CoseAlg::AesCcm64_64_128 => "AES-CCM-64-128/64"
    CoseAlg::AesCcm64_64_256 => "AES-CCM-64-256/64"
    CoseAlg::AesCcm16_128_128 => "AES-CCM-16-128/128"
    CoseAlg::AesCcm16_128_256 => "AES-CCM-16-256/128"
    CoseAlg::AesCcm64_128_128 => "AES-CCM-64-128/128"
    CoseAlg::AesCcm64_128_256 => "AES-CCM-64-256/128"
    CoseAlg::Int(n) => "int(\{n})"
    CoseAlg::Text(s) => s
  }
}

///|
/// Header map label: a CBOR int or text string (RFC 9052).
pub(all) enum Label {
  Int(Int32)
  Text(String)
} derive(Eq)

///|
pub extend Label with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Label with Eq::{not_equal}

///|
/// Encode a header label as a CBOR int or text string.
pub fn Label::to_cbor(self : Label) -> @cbor.CborValue {
  match self {
    Label::Int(n) => @cbor.Integer(n.to_int64())
    Label::Text(s) => @cbor.Text(s)
  }
}

///|
/// Read a header label from a CBOR int or text string.
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
} derive(Eq)

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
