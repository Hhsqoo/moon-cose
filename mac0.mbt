///|
/// COSE_Mac0 (RFC 9052). Tag 17 when `tagged` is true.
pub(all) struct Mac0 {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  payload : Bytes?
  tag : Bytes
} derive(Eq, Debug)

///|
pub extend Mac0 with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Mac0 with Eq::{not_equal}

///|
pub fn Mac0::mac(
  protected_header : Header,
  unprotected : Header,
  payload : Bytes?,
  external_aad : Bytes,
  key : CoseKey,
  tagged~ : Bool = true,
) -> Mac0 raise CoseError {
  let prot = Protected::from_header(protected_header)
  let alg = resolve_alg(prot.header, unprotected)
  check_key_alg(key.algorithm(), alg)
  let tbs = mac_structure(
    "MAC0",
    prot.raw,
    external_aad,
    payload_bytes(payload),
  )
  {
    tagged,
    protected_header: prot,
    unprotected,
    payload,
    tag: mac_with(alg, key, tbs),
  }
}

///|
pub fn Mac0::decode(bytes : Bytes) -> Mac0 raise CoseError {
  let (tagged, items) = decode_message(bytes, 17UL, 4, "COSE_Mac0")
  let raw = cbor_bstr_field(items[0], "protected header")
  {
    tagged,
    protected_header: Protected::from_raw(raw),
    unprotected: Header::from_cbor(items[1]),
    payload: cbor_payload_field(items[2]),
    tag: cbor_bstr_field(items[3], "tag"),
  }
}

///|
pub fn Mac0::encode(self : Mac0) -> Bytes {
  encode_tagged(17UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.payload),
    @cbor.Bytes(self.tag),
  ])
}

///|
pub fn Mac0::verify(
  self : Mac0,
  external_aad : Bytes,
  key : CoseKey,
) -> Unit raise CoseError {
  let alg = resolve_alg(self.protected_header.header, self.unprotected)
  check_key_alg(key.algorithm(), alg)
  let tbs = mac_structure(
    "MAC0",
    self.protected_header.raw,
    external_aad,
    payload_bytes(self.payload),
  )
  check_mac(alg, key, tbs, self.tag)
}
