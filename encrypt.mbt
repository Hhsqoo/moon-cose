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
/// Decode a tagged (96) or untagged COSE_Encrypt array.
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
/// Encode this COSE_Encrypt, using tag 96 when `tagged` is true.
pub fn Encrypt::encode(self : Encrypt) -> Bytes {
  encode_tagged(96UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.ciphertext),
    encode_recipients(self.recipients),
  ])
}

///|
/// Encrypt for one or more recipients. Each recipient uses direct or AES Key Wrap.
/// `cek` is the content key; direct recipients must hold the same bytes.
pub fn Encrypt::encrypt(
  protected_header : Header,
  unprotected : Header,
  plaintext : Bytes,
  external_aad : Bytes,
  cek : Bytes,
  recipients : Array[RecipientInput],
  tagged~ : Bool = true,
) -> Encrypt raise CoseError {
  if recipients.length() == 0 {
    raise BadStructure("COSE_Encrypt needs at least one recipient")
  }
  let prot = Protected::from_header(protected_header)
  let alg = resolve_alg(prot.header, unprotected)
  let iv = resolve_iv(alg, prot.header, unprotected, None)
  let built : Array[Recipient] = []
  for i = 0; i < recipients.length(); i = i + 1 {
    built.push(seal_recipient(recipients[i], cek))
  }
  let aad = enc_structure("Encrypt", prot.raw, external_aad)
  {
    tagged,
    protected_header: prot,
    unprotected,
    ciphertext: Some(content_seal(alg, cek, iv, aad, plaintext)),
    recipients: built,
  }
}

///|
fn seal_recipient(
  input : RecipientInput,
  cek : Bytes,
) -> Recipient raise CoseError {
  let alg = match input.unprotected.alg {
    Some(value) => value.normalize()
    None => raise BadStructure("recipient alg is missing")
  }
  check_key_alg(input.key.algorithm(), alg)
  let ciphertext = match alg {
    CoseAlg::Direct => {
      if !bytes_eq(symmetric_key(input.key), cek) {
        raise BadStructure("direct recipient key is not the content key")
      }
      None
    }
    CoseAlg::A128KW | CoseAlg::A192KW | CoseAlg::A256KW =>
      Some(kw_wrap(alg, symmetric_key(input.key), cek))
    other => raise UnsupportedAlg(other.name())
  }
  {
    protected_header: Protected::from_header(Header::empty()),
    unprotected: input.unprotected,
    ciphertext,
  }
}

///|
/// Open the message with one recipient key. The key's kid must match when both sides have one.
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
