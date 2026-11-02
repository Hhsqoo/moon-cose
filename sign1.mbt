///|
/// COSE_Sign1 (RFC 9052). Tag 18 when `tagged` is true.
pub(all) struct Sign1 {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  payload : Bytes?
  signature : Bytes
} derive(Eq)

///|
pub extend Sign1 with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Sign1 with Eq::{not_equal}

///|
fn sign1_alg(msg : Sign1) -> CoseAlg raise CoseError {
  match msg.protected_header.header.alg {
    None => raise BadStructure("Sign1 alg must be in the protected header")
    Some(_) => resolve_alg(msg.protected_header.header, msg.unprotected)
  }
}

///|
pub fn Sign1::sign(
  protected_header : Header,
  unprotected : Header,
  payload : Bytes?,
  external_aad : Bytes,
  key : CoseKey,
  tagged~ : Bool = true,
) -> Sign1 raise CoseError {
  let msg : Sign1 = {
    tagged,
    protected_header: Protected::from_header(protected_header),
    unprotected,
    payload,
    signature: b"",
  }
  let alg = sign1_alg(msg)
  check_key_alg(key.algorithm(), alg)
  let tbs = sig_structure(
    "Signature1",
    msg.protected_header.raw,
    None,
    external_aad,
    payload_bytes(payload),
  )
  { ..msg, signature: sign_with(alg, key, tbs), }
}

///|
pub fn Sign1::decode(bytes : Bytes) -> Sign1 raise CoseError {
  let (tagged, items) = decode_message(bytes, 18UL, 4, "COSE_Sign1")
  let raw = cbor_bstr_field(items[0], "protected header")
  {
    tagged,
    protected_header: Protected::from_raw(raw),
    unprotected: Header::from_cbor(items[1]),
    payload: cbor_payload_field(items[2]),
    signature: cbor_bstr_field(items[3], "signature"),
  }
}

///|
pub fn Sign1::encode(self : Sign1) -> Bytes {
  encode_tagged(18UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.payload),
    @cbor.Bytes(self.signature),
  ])
}

///|
pub fn Sign1::verify(
  self : Sign1,
  external_aad : Bytes,
  key : CoseKey,
) -> Unit raise CoseError {
  let alg = sign1_alg(self)
  check_key_alg(key.algorithm(), alg)
  let tbs = sig_structure(
    "Signature1",
    self.protected_header.raw,
    None,
    external_aad,
    payload_bytes(self.payload),
  )
  verify_with(alg, key, tbs, self.signature)
}
