///|
/// One COSE_recipient (RFC 9052). `ciphertext` is nil or empty for direct,
/// and the wrapped CEK for AES Key Wrap.
pub(all) struct Recipient {
  protected_header : Protected
  unprotected : Header
  ciphertext : Bytes?
} derive(Eq)

///|
pub extend Recipient with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Recipient with Eq::{not_equal}

///|
/// Inputs for building one recipient. `unprotected.alg` selects direct or AES Key Wrap.
pub(all) struct RecipientInput {
  unprotected : Header
  key : CoseKey
}

///|
fn header_kid(header : Header) -> Bytes? {
  header.kid
}

///|
fn recipient_kid(recipient : Recipient) -> Bytes? {
  match header_kid(recipient.unprotected) {
    Some(kid) => Some(kid)
    None => header_kid(recipient.protected_header.header)
  }
}

///|
fn kid_matches(key : CoseKey, recipient : Recipient) -> Bool {
  match (key.kid(), recipient_kid(recipient)) {
    (Some(left), Some(right)) => bytes_eq(left, right)
    _ => true
  }
}

///|
fn decode_recipients(
  value : @cbor.CborValue,
) -> Array[Recipient] raise CoseError {
  match value {
    @cbor.Array(rows) => {
      if rows.length() == 0 {
        raise BadStructure("COSE message needs at least one recipient")
      }
      let out : Array[Recipient] = []
      for i = 0; i < rows.length(); i = i + 1 {
        match rows[i] {
          @cbor.Array(row) => {
            if row.length() != 3 {
              raise BadStructure("COSE_recipient must have 3 items")
            }
            let raw = cbor_bstr_field(row[0], "recipient protected header")
            let ciphertext = match row[2] {
              @cbor.Bytes(b) => if b.length() == 0 { None } else { Some(b) }
              @cbor.Simple(22) => None
              _ =>
                raise BadStructure(
                  "recipient ciphertext must be a bstr or null",
                )
            }
            out.push({
              protected_header: Protected::from_raw(raw),
              unprotected: Header::from_cbor(row[1]),
              ciphertext,
            })
          }
          _ => raise BadStructure("COSE_recipient must be an array")
        }
      }
      out
    }
    _ => raise BadStructure("recipients must be an array")
  }
}

///|
fn encode_recipients(recipients : Array[Recipient]) -> @cbor.CborValue {
  let rows : Array[@cbor.CborValue] = []
  for i = 0; i < recipients.length(); i = i + 1 {
    let recipient = recipients[i]
    rows.push(
      @cbor.Array([
        @cbor.Bytes(recipient.protected_header.raw),
        recipient.unprotected.to_cbor(),
        payload_to_cbor(recipient.ciphertext),
      ]),
    )
  }
  @cbor.Array(rows)
}

///|
/// Recover the content encryption key from one recipient.
/// `direct` (-6) returns the symmetric key itself.
/// A128KW / A192KW / A256KW unwrap the recipient ciphertext.
fn open_recipient(
  recipient : Recipient,
  key : CoseKey,
) -> Bytes raise CoseError {
  let alg = resolve_alg(
    recipient.protected_header.header,
    recipient.unprotected,
  )
  check_key_alg(key.algorithm(), alg)
  match alg.normalize() {
    CoseAlg::Direct => symmetric_key(key)
    CoseAlg::A128KW | CoseAlg::A192KW | CoseAlg::A256KW =>
      match recipient.ciphertext {
        Some(wrapped) => kw_unwrap(alg, symmetric_key(key), wrapped)
        None =>
          raise BadStructure("AES Key Wrap recipient is missing ciphertext")
      }
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn open_cek(
  recipients : Array[Recipient],
  key : CoseKey,
) -> Bytes raise CoseError {
  let mut last : CoseError = BadStructure("no recipient matched the key")
  let mut saw = false
  for i = 0; i < recipients.length(); i = i + 1 {
    if !kid_matches(key, recipients[i]) {
      continue
    }
    saw = true
    try {
      return open_recipient(recipients[i], key)
    } catch {
      err => last = err
    }
  }
  if !saw {
    raise BadStructure("no recipient matched the key")
  }
  raise last
}
