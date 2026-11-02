///|
fn bytes_slice(b : Bytes, start : Int32, end : Int32) -> Bytes {
  let out = Array::make(end - start, b'\x00')
  for i = start; i < end; i = i + 1 {
    out[i - start] = b[i]
  }
  Bytes::from_array(out)
}

///|
fn bytes_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
fn bytes_empty() -> Bytes {
  Bytes::from_array([])
}

///|
fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out)
}

///|
fn decode_cbor(bytes : Bytes) -> @cbor.CborValue raise CoseError {
  @cbor.decode(bytes) catch {
    err => raise MalformedCbor(err.to_string())
  }
}

///|
fn int_from_i64(v : Int64) -> Int32 raise CoseError {
  if v > 2147483647L || v < -2147483648L {
    raise BadStructure("CBOR integer does not fit in Int")
  }
  v.to_int()
}
