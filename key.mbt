///|
/// Octet key pair (RFC 9053). `crv` 6 is Ed25519. `d` is the 32-byte seed.
pub(all) struct OkpKey {
  crv : Int32
  x : Bytes
  d : Bytes?
  kid : Bytes?
  alg : CoseAlg?
  key_ops : Array[Int32]
  base_iv : Bytes?
} derive(Eq)

///|
pub extend OkpKey with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend OkpKey with Eq::{not_equal}

///|
/// Elliptic curve key (RFC 9053). `crv` 1 is P-256. `d`, `x`, and `y` are
/// 32-byte big-endian coordinates.
pub(all) struct Ec2Key {
  crv : Int32
  x : Bytes
  y : Bytes?
  d : Bytes?
  kid : Bytes?
  alg : CoseAlg?
  key_ops : Array[Int32]
  base_iv : Bytes?
} derive(Eq)

///|
pub extend Ec2Key with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend Ec2Key with Eq::{not_equal}

///|
/// Symmetric key. `k` is the raw key bytes.
pub(all) struct SymKey {
  k : Bytes
  kid : Bytes?
  alg : CoseAlg?
  key_ops : Array[Int32]
  base_iv : Bytes?
} derive(Eq)

///|
pub extend SymKey with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend SymKey with Eq::{not_equal}

///|
pub(all) enum CoseKey {
  Okp(OkpKey)
  Ec2(Ec2Key)
  Sym(SymKey)
} derive(Eq)

///|
pub extend CoseKey with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend CoseKey with Eq::{not_equal}

///|
pub fn CoseKey::algorithm(self : CoseKey) -> CoseAlg? {
  match self {
    CoseKey::Okp(key) => key.alg
    CoseKey::Ec2(key) => key.alg
    CoseKey::Sym(key) => key.alg
  }
}

///|
pub fn OkpKey::ed25519(x : Bytes, d : Bytes?) -> OkpKey {
  { crv: 6, x, d, kid: None, alg: None, key_ops: [], base_iv: None, }
}

///|
pub fn Ec2Key::p256(x : Bytes, y : Bytes?, d : Bytes?) -> Ec2Key {
  { crv: 1, x, y, d, kid: None, alg: None, key_ops: [], base_iv: None, }
}

///|
pub fn SymKey::new(k : Bytes) -> SymKey {
  { k, kid: None, alg: None, key_ops: [], base_iv: None, }
}

///|
priv struct KeyParts {
  kty : Int32?
  kid : Bytes?
  alg : CoseAlg?
  key_ops : Array[Int32]
  base_iv : Bytes?
  crv : Int32?
  x : Bytes?
  y : Bytes?
  d : Bytes?
  k : Bytes?
}

///|
fn cbor_small_int(
  value : @cbor.CborValue,
  what : String,
) -> Int32 raise CoseError {
  match value {
    @cbor.Integer(n) => int_from_i64(n)
    @cbor.Unsigned(n) =>
      if n > 2147483647UL {
        raise BadStructure("\{what} integer is too large")
      } else {
        n.to_int()
      }
    _ => raise BadStructure("\{what} must be an integer")
  }
}

///|
fn key_ops_from_cbor(value : @cbor.CborValue) -> Array[Int32] raise CoseError {
  match value {
    @cbor.Array(items) => {
      let out : Array[Int32] = []
      for i = 0; i < items.length(); i = i + 1 {
        out.push(cbor_small_int(items[i], "key_ops"))
      }
      out
    }
    _ => raise BadStructure("key_ops must be an array of integers")
  }
}

///|
pub fn CoseKey::from_cbor(value : @cbor.CborValue) -> CoseKey raise CoseError {
  match value {
    @cbor.Map(pairs) => parts_to_key(read_key_parts(pairs))
    _ => raise BadStructure("COSE_Key is not a map")
  }
}

///|
fn read_key_parts(
  pairs : Array[(@cbor.CborValue, @cbor.CborValue)],
) -> KeyParts raise CoseError {
  let mut kty = None
  let mut kid = None
  let mut alg = None
  let mut key_ops = []
  let mut base_iv = None
  let mut crv = None
  let mut x = None
  let mut y = None
  let mut d = None
  let mut k = None
  let seen : Array[Label] = []
  for i = 0; i < pairs.length(); i = i + 1 {
    let label = Label::from_cbor(pairs[i].0)
    if seen_label(seen, label) {
      raise BadStructure("duplicate COSE_Key label")
    }
    seen.push(label)
    let item = pairs[i].1
    match label {
      Label::Int(1) => kty = Some(cbor_small_int(item, "kty"))
      Label::Int(2) => kid = Some(expect_bytes(item, "kid"))
      Label::Int(3) => alg = Some(CoseAlg::from_cbor(item))
      Label::Int(4) => key_ops = key_ops_from_cbor(item)
      Label::Int(5) => base_iv = Some(expect_bytes(item, "Base IV"))
      Label::Int(-1) =>
        match item {
          @cbor.Bytes(b) => k = Some(b)
          _ => crv = Some(cbor_small_int(item, "crv"))
        }
      Label::Int(-2) => x = Some(expect_bytes(item, "x"))
      Label::Int(-3) => y = Some(expect_bytes(item, "y"))
      Label::Int(-4) => d = Some(expect_bytes(item, "d"))
      _ => raise BadStructure("unsupported COSE_Key label")
    }
  }
  { kty, kid, alg, key_ops, base_iv, crv, x, y, d, k, }
}

///|
fn parts_to_key(parts : KeyParts) -> CoseKey raise CoseError {
  match parts.kty {
    None => raise BadStructure("COSE_Key is missing kty")
    Some(1) => {
      let crv = match parts.crv {
        Some(c) => c
        None => raise BadStructure("OKP key is missing crv")
      }
      let x = match parts.x {
        Some(b) => b
        None => raise BadStructure("OKP key is missing x")
      }
      CoseKey::Okp({
        crv,
        x,
        d: parts.d,
        kid: parts.kid,
        alg: parts.alg,
        key_ops: parts.key_ops,
        base_iv: parts.base_iv,
      })
    }
    Some(2) => {
      let crv = match parts.crv {
        Some(c) => c
        None => raise BadStructure("EC2 key is missing crv")
      }
      let x = match parts.x {
        Some(b) => b
        None => raise BadStructure("EC2 key is missing x")
      }
      CoseKey::Ec2({
        crv,
        x,
        y: parts.y,
        d: parts.d,
        kid: parts.kid,
        alg: parts.alg,
        key_ops: parts.key_ops,
        base_iv: parts.base_iv,
      })
    }
    Some(4) => {
      let k = match parts.k {
        Some(b) => b
        None => raise BadStructure("symmetric key is missing k")
      }
      CoseKey::Sym({
        k,
        kid: parts.kid,
        alg: parts.alg,
        key_ops: parts.key_ops,
        base_iv: parts.base_iv,
      })
    }
    Some(other) => raise BadStructure("unsupported kty \{other}")
  }
}

///|
fn push_common(
  pairs : Array[(@cbor.CborValue, @cbor.CborValue)],
  kty : Int32,
  kid : Bytes?,
  alg : CoseAlg?,
  key_ops : Array[Int32],
  base_iv : Bytes?,
) -> Unit {
  pairs.push((@cbor.Integer(1L), @cbor.Integer(kty.to_int64())))
  match kid {
    Some(b) => pairs.push((@cbor.Integer(2L), @cbor.Bytes(b)))
    None => ()
  }
  match alg {
    Some(a) => pairs.push((@cbor.Integer(3L), a.to_cbor()))
    None => ()
  }
  if key_ops.length() > 0 {
    let ops : Array[@cbor.CborValue] = []
    for i = 0; i < key_ops.length(); i = i + 1 {
      ops.push(@cbor.Integer(key_ops[i].to_int64()))
    }
    pairs.push((@cbor.Integer(4L), @cbor.Array(ops)))
  }
  match base_iv {
    Some(b) => pairs.push((@cbor.Integer(5L), @cbor.Bytes(b)))
    None => ()
  }
}

///|
pub fn CoseKey::to_cbor(self : CoseKey) -> @cbor.CborValue {
  let pairs : Array[(@cbor.CborValue, @cbor.CborValue)] = []
  match self {
    CoseKey::Okp(key) => {
      push_common(pairs, 1, key.kid, key.alg, key.key_ops, key.base_iv)
      pairs.push((@cbor.Integer(-1L), @cbor.Integer(key.crv.to_int64())))
      pairs.push((@cbor.Integer(-2L), @cbor.Bytes(key.x)))
      match key.d {
        Some(d) => pairs.push((@cbor.Integer(-4L), @cbor.Bytes(d)))
        None => ()
      }
    }
    CoseKey::Ec2(key) => {
      push_common(pairs, 2, key.kid, key.alg, key.key_ops, key.base_iv)
      pairs.push((@cbor.Integer(-1L), @cbor.Integer(key.crv.to_int64())))
      pairs.push((@cbor.Integer(-2L), @cbor.Bytes(key.x)))
      match key.y {
        Some(y) => pairs.push((@cbor.Integer(-3L), @cbor.Bytes(y)))
        None => ()
      }
      match key.d {
        Some(d) => pairs.push((@cbor.Integer(-4L), @cbor.Bytes(d)))
        None => ()
      }
    }
    CoseKey::Sym(key) => {
      push_common(pairs, 4, key.kid, key.alg, key.key_ops, key.base_iv)
      pairs.push((@cbor.Integer(-1L), @cbor.Bytes(key.k)))
    }
  }
  @cbor.Map(pairs)
}

///|
pub fn CoseKey::encode(self : CoseKey) -> Bytes {
  @cbor.encode(self.to_cbor())
}

///|
pub fn CoseKey::decode(bytes : Bytes) -> CoseKey raise CoseError {
  CoseKey::from_cbor(decode_cbor(bytes))
}
