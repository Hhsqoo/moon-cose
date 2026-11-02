///|
/// COSE_Mac (RFC 9052 §6.1). Tag 97 when `tagged` is true.
pub(all) struct Mac {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  payload : Bytes?
  tag : Bytes
  recipients : Array[Recipient]
} derive(Eq)

///|
pub extend Mac with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Mac with Eq::{not_equal}

///|
pub fn Mac::decode(bytes : Bytes) -> Mac raise CoseError {
  let (tagged, items) = decode_message(bytes, 97UL, 5, "COSE_Mac")
  let raw = cbor_bstr_field(items[0], "protected header")
  {
    tagged,
    protected_header: Protected::from_raw(raw),
    unprotected: Header::from_cbor(items[1]),
    payload: cbor_payload_field(items[2]),
    tag: cbor_bstr_field(items[3], "tag"),
    recipients: decode_recipients(items[4]),
  }
}

///|
pub fn Mac::encode(self : Mac) -> Bytes {
  encode_tagged(97UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.payload),
    @cbor.Bytes(self.tag),
    encode_recipients(self.recipients),
  ])
}

///|
pub fn Mac::verify(
  self : Mac,
  external_aad : Bytes,
  key : CoseKey,
) -> Unit raise CoseError {
  let cek = open_cek(self.recipients, key)
  let alg = resolve_alg(self.protected_header.header, self.unprotected)
  let tbs = mac_structure(
    "MAC",
    self.protected_header.raw,
    external_aad,
    payload_bytes(self.payload),
  )
  check_mac(alg, CoseKey::Sym(SymKey::new(cek)), tbs, self.tag)
}
