///|
/// COSE_Encrypt (RFC 9052 §5.1). Tag 96 when `tagged` is true.
pub(all) struct Encrypt {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  ciphertext : Bytes?
  recipients : Array[Recipient]
} derive(Eq)

///|
pub extend Encrypt with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Encrypt with Eq::{not_equal}

///|
pub fn Encrypt::decode(bytes : Bytes) -> Encrypt raise CoseError {
  let (tagged, items) = decode_message(bytes, 96UL, 4, "COSE_Encrypt")
  let raw = cbor_bstr_field(items[0], "protected header")
  let ciphertext = match items[2] {
    @cbor.Bytes(b) => Some(b)
    @cbor.Simple(22) => None
    _ => raise BadStructure("ciphertext must be a byte string or null")
  }
  {
    tagged,
    protected_header: Protected::from_raw(raw),
    unprotected: Header::from_cbor(items[1]),
    ciphertext,
    recipients: decode_recipients(items[3]),
  }
}

///|
pub fn Encrypt::encode(self : Encrypt) -> Bytes {
  encode_tagged(96UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.ciphertext),
    encode_recipients(self.recipients),
  ])
}

///|
pub fn Encrypt::decrypt(
  self : Encrypt,
  external_aad : Bytes,
  key : CoseKey,
) -> Bytes raise CoseError {
  let cek = open_cek(self.recipients, key)
  let alg = resolve_alg(self.protected_header.header, self.unprotected)
  let iv = resolve_iv(
    alg,
    self.protected_header.header,
    self.unprotected,
    key.base_iv(),
  )
  let aad = enc_structure("Encrypt", self.protected_header.raw, external_aad)
  match self.ciphertext {
    None => raise DecryptionFailed
    Some(ct) => content_open(alg, cek, iv, aad, ct)
  }
}
