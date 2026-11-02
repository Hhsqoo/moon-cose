///|
fn bstr_cbor(bytes : Bytes) -> @cbor.CborValue {
  @cbor.Bytes(bytes)
}

///|
fn text_cbor(text : String) -> @cbor.CborValue {
  @cbor.Text(text)
}

///|
fn payload_bytes(payload : Bytes?) -> Bytes {
  match payload {
    Some(b) => b
    None => bytes_empty()
  }
}

///|
/// `Sig_structure` from RFC 9052. `sign_protected` is present only for the
/// `"Signature"` and `"CounterSignature"` contexts.
pub fn sig_structure(
  context : String,
  body_protected : Bytes,
  sign_protected : Bytes?,
  external_aad : Bytes,
  payload : Bytes,
) -> Bytes {
  let items : Array[@cbor.CborValue] = [
    text_cbor(context),
    bstr_cbor(body_protected),
  ]
  match sign_protected {
    Some(raw) => items.push(bstr_cbor(raw))
    None => ()
  }
  items.push(bstr_cbor(external_aad))
  items.push(bstr_cbor(payload))
  @cbor.encode(@cbor.Array(items))
}

///|
/// `MAC_structure` from RFC 9052. `context` is `"MAC0"` or `"MAC"`.
pub fn mac_structure(
  context : String,
  prot : Bytes,
  external_aad : Bytes,
  payload : Bytes,
) -> Bytes {
  @cbor.encode(
    @cbor.Array([
      text_cbor(context),
      bstr_cbor(prot),
      bstr_cbor(external_aad),
      bstr_cbor(payload),
    ]),
  )
}

///|
/// `Enc_structure` from RFC 9052. This byte string is the AEAD AAD.
/// `context` is `"Encrypt0"` or `"Encrypt"`.
pub fn enc_structure(
  context : String,
  prot : Bytes,
  external_aad : Bytes,
) -> Bytes {
  @cbor.encode(
    @cbor.Array([text_cbor(context), bstr_cbor(prot), bstr_cbor(external_aad)]),
  )
}

///|
fn decode_message(
  bytes : Bytes,
  expected_tag : UInt64,
  arity : Int32,
  what : String,
) -> (Bool, Array[@cbor.CborValue]) raise CoseError {
  let value = decode_cbor(bytes)
  match value {
    @cbor.Array(items) => {
      if items.length() != arity {
        raise BadStructure("\{what} has \{items.length()} items, want \{arity}")
      }
      (false, items)
    }
    @cbor.Tag(tag, @cbor.Array(items)) => {
      if tag != expected_tag {
        raise BadStructure("unexpected CBOR tag for \{what}")
      }
      if items.length() != arity {
        raise BadStructure("\{what} has \{items.length()} items, want \{arity}")
      }
      (true, items)
    }
    @cbor.Tag(_, _) => raise BadStructure("\{what} tag does not wrap an array")
    _ => raise BadStructure("\{what} is not an array")
  }
}

///|
fn cbor_bstr_field(
  value : @cbor.CborValue,
  what : String,
) -> Bytes raise CoseError {
  match value {
    @cbor.Bytes(b) => b
    _ => raise BadStructure("\{what} must be a byte string")
  }
}

///|
fn cbor_payload_field(value : @cbor.CborValue) -> Bytes? raise CoseError {
  match value {
    @cbor.Bytes(b) => Some(b)
    @cbor.Simple(22) => None
    _ => raise BadStructure("payload must be a byte string or null")
  }
}

///|
fn payload_to_cbor(payload : Bytes?) -> @cbor.CborValue {
  match payload {
    Some(b) => @cbor.Bytes(b)
    None => @cbor.Simple(22)
  }
}

///|
fn encode_tagged(
  tag : UInt64,
  tagged : Bool,
  items : Array[@cbor.CborValue],
) -> Bytes {
  let value = if tagged {
    @cbor.Tag(tag, @cbor.Array(items))
  } else {
    @cbor.Array(items)
  }
  @cbor.encode(value)
}
