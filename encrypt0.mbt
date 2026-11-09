///|
/// COSE_Encrypt0 (RFC 9052). Tag 16 when `tagged` is true.
/// AES-GCM ciphertext is `ciphertext || 16-byte tag`.
pub(all) struct Encrypt0 {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  ciphertext : Bytes?
} derive(Eq)

///|
pub extend Encrypt0 with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Encrypt0 with Eq::{not_equal}

///|
fn encrypt_alg(msg : Encrypt0) -> CoseAlg raise CoseError {
  resolve_alg(msg.protected_header.header, msg.unprotected)
}

///|
/// Encrypt with one key and no recipients. The content algorithm comes from the headers.
pub fn Encrypt0::encrypt(
  protected_header : Header,
  unprotected : Header,
  plaintext : Bytes,
  external_aad : Bytes,
  key : CoseKey,
  tagged~ : Bool = true,
) -> Encrypt0 raise CoseError {
  let prot = Protected::from_header(protected_header)
  let draft : Encrypt0 = {
    tagged,
    protected_header: prot,
    unprotected,
    ciphertext: None,
  }
  let alg = encrypt_alg(draft)
  check_key_alg(key.algorithm(), alg)
  let iv = resolve_iv(alg, prot.header, unprotected, key.base_iv())
  let aad = enc_structure("Encrypt0", prot.raw, external_aad)
  {
    ..draft,
    ciphertext: Some(content_seal(alg, symmetric_key(key), iv, aad, plaintext)),
  }
}

///|
/// Decode a tagged (16) or untagged COSE_Encrypt0 array.
pub fn Encrypt0::decode(bytes : Bytes) -> Encrypt0 raise CoseError {
  let (tagged, items) = decode_message(bytes, 16UL, 3, "COSE_Encrypt0")
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
  }
}

///|
/// Encode this COSE_Encrypt0, using tag 16 when `tagged` is true.
pub fn Encrypt0::encode(self : Encrypt0) -> Bytes {
  encode_tagged(16UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.ciphertext),
  ])
}

///|
/// Decrypt and check the AEAD tag. A partial IV is expanded with the key's Base IV.
pub fn Encrypt0::decrypt(
  self : Encrypt0,
  external_aad : Bytes,
  key : CoseKey,
) -> Bytes raise CoseError {
  let alg = encrypt_alg(self)
  check_key_alg(key.algorithm(), alg)
  let iv = resolve_iv(
    alg,
    self.protected_header.header,
    self.unprotected,
    key.base_iv(),
  )
  let aad = enc_structure("Encrypt0", self.protected_header.raw, external_aad)
  match self.ciphertext {
    None => raise DecryptionFailed
    Some(ct) => content_open(alg, symmetric_key(key), iv, aad, ct)
  }
}
