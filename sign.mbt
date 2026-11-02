///|
/// One signer inside COSE_Sign.
pub(all) struct Signer {
  protected_header : Protected
  unprotected : Header
  signature : Bytes
} derive(Eq, Debug)

///|
pub extend Signer with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Signer with Eq::{not_equal}

///|
/// Material for one signature over a COSE_Sign body.
pub(all) struct SignerInput {
  protected_header : Header
  unprotected : Header
  key : CoseKey
}

///|
/// COSE_Sign (RFC 9052), including the multi-signer form. Tag 98 when tagged.
pub(all) struct Sign {
  tagged : Bool
  protected_header : Protected
  unprotected : Header
  payload : Bytes?
  signatures : Array[Signer]
} derive(Eq, Debug)

///|
pub extend Sign with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Sign with Eq::{not_equal}

///|
fn signer_alg(signer : Signer) -> CoseAlg raise CoseError {
  match signer.protected_header.header.alg {
    None => raise BadStructure("signer alg must be in the protected header")
    Some(_) => resolve_alg(signer.protected_header.header, signer.unprotected)
  }
}

///|
pub fn Sign::sign(
  protected_header : Header,
  unprotected : Header,
  payload : Bytes?,
  signers : Array[SignerInput],
  external_aad : Bytes,
  tagged~ : Bool = true,
) -> Sign raise CoseError {
  if signers.length() == 0 {
    raise BadStructure("COSE_Sign needs at least one signer")
  }
  let body = Protected::from_header(protected_header)
  let signatures : Array[Signer] = []
  for i = 0; i < signers.length(); i = i + 1 {
    let input = signers[i]
    let prot = Protected::from_header(input.protected_header)
    let draft : Signer = {
      protected_header: prot,
      unprotected: input.unprotected,
      signature: b"",
    }
    let alg = signer_alg(draft)
    check_key_alg(input.key.algorithm(), alg)
    let tbs = sig_structure(
      "Signature",
      body.raw,
      Some(prot.raw),
      external_aad,
      payload_bytes(payload),
    )
    signatures.push({ ..draft, signature: sign_with(alg, input.key, tbs), })
  }
  { tagged, protected_header: body, unprotected, payload, signatures, }
}

///|
pub fn Sign::decode(bytes : Bytes) -> Sign raise CoseError {
  let (tagged, items) = decode_message(bytes, 98UL, 4, "COSE_Sign")
  let raw = cbor_bstr_field(items[0], "protected header")
  let sigs = match items[3] {
    @cbor.Array(rows) => rows
    _ => raise BadStructure("COSE_Sign signatures must be an array")
  }
  if sigs.length() == 0 {
    raise BadStructure("COSE_Sign needs at least one signer")
  }
  let signatures : Array[Signer] = []
  for i = 0; i < sigs.length(); i = i + 1 {
    match sigs[i] {
      @cbor.Array(row) => {
        if row.length() != 3 {
          raise BadStructure("COSE_Signature must have 3 items")
        }
        let signer_raw = cbor_bstr_field(row[0], "signer protected header")
        signatures.push({
          protected_header: Protected::from_raw(signer_raw),
          unprotected: Header::from_cbor(row[1]),
          signature: cbor_bstr_field(row[2], "signature"),
        })
      }
      _ => raise BadStructure("COSE_Signature must be an array")
    }
  }
  {
    tagged,
    protected_header: Protected::from_raw(raw),
    unprotected: Header::from_cbor(items[1]),
    payload: cbor_payload_field(items[2]),
    signatures,
  }
}

///|
pub fn Sign::encode(self : Sign) -> Bytes {
  let rows : Array[@cbor.CborValue] = []
  for i = 0; i < self.signatures.length(); i = i + 1 {
    let signer = self.signatures[i]
    rows.push(
      @cbor.Array([
        @cbor.Bytes(signer.protected_header.raw),
        signer.unprotected.to_cbor(),
        @cbor.Bytes(signer.signature),
      ]),
    )
  }
  encode_tagged(98UL, self.tagged, [
    @cbor.Bytes(self.protected_header.raw),
    self.unprotected.to_cbor(),
    payload_to_cbor(self.payload),
    @cbor.Array(rows),
  ])
}

///|
pub fn Sign::verify_signer(
  self : Sign,
  index : Int32,
  external_aad : Bytes,
  key : CoseKey,
) -> Unit raise CoseError {
  if index < 0 || index >= self.signatures.length() {
    raise BadStructure("signer index is out of range")
  }
  let signer = self.signatures[index]
  let alg = signer_alg(signer)
  check_key_alg(key.algorithm(), alg)
  let tbs = sig_structure(
    "Signature",
    self.protected_header.raw,
    Some(signer.protected_header.raw),
    external_aad,
    payload_bytes(self.payload),
  )
  verify_with(alg, key, tbs, signer.signature)
}
