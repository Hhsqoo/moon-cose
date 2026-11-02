///|
fn require_len(bytes : Bytes, n : Int32, what : String) -> Unit raise CoseError {
  if bytes.length() != n {
    raise BadStructure("\{what} must be \{n} bytes")
  }
}

///|
fn ed25519_seed(key : CoseKey) -> Bytes raise CoseError {
  match key {
    CoseKey::Okp(okp) =>
      if okp.crv != 6 {
        raise AlgMismatch("EdDSA signing requires an Ed25519 OKP key")
      } else {
        match okp.d {
          Some(seed) => {
            require_len(seed, 32, "Ed25519 seed")
            seed
          }
          None => raise BadStructure("Ed25519 private key is missing d")
        }
      }
    _ => raise AlgMismatch("EdDSA signing requires an OKP key")
  }
}

///|
fn ed25519_public(key : CoseKey) -> Bytes raise CoseError {
  match key {
    CoseKey::Okp(okp) =>
      if okp.crv != 6 {
        raise AlgMismatch("EdDSA verification requires an Ed25519 OKP key")
      } else if okp.x.length() == 32 {
        okp.x
      } else {
        match okp.d {
          Some(seed) => {
            require_len(seed, 32, "Ed25519 seed")
            @lib.ed25519_public_key(seed)
          }
          None => raise BadStructure("Ed25519 public key is missing x")
        }
      }
    _ => raise AlgMismatch("EdDSA verification requires an OKP key")
  }
}

///|
fn p256_private(key : CoseKey) -> Bytes raise CoseError {
  match key {
    CoseKey::Ec2(ec2) =>
      if ec2.crv != 1 {
        raise AlgMismatch("ES256 signing requires a P-256 key")
      } else {
        match ec2.d {
          Some(d) => {
            require_len(d, 32, "P-256 private scalar")
            d
          }
          None => raise BadStructure("P-256 private key is missing d")
        }
      }
    _ => raise AlgMismatch("ES256 signing requires an EC2 key")
  }
}

///|
fn p256_public(key : CoseKey) -> Bytes raise CoseError {
  match key {
    CoseKey::Ec2(ec2) =>
      if ec2.crv != 1 {
        raise AlgMismatch("ES256 verification requires a P-256 key")
      } else {
        match (ec2.y, ec2.d) {
          (Some(y), _) => {
            require_len(ec2.x, 32, "P-256 x")
            require_len(y, 32, "P-256 y")
            let out = Array::make(65, b'\x00')
            out[0] = b'\x04'
            for i = 0; i < 32; i = i + 1 {
              out[1 + i] = ec2.x[i]
              out[33 + i] = y[i]
            }
            Bytes::from_array(out)
          }
          (None, Some(d)) => {
            require_len(d, 32, "P-256 private scalar")
            @lib.ecdsa_p256_public_key(d)
          }
          (None, None) => raise BadStructure("P-256 public key is missing y")
        }
      }
    _ => raise AlgMismatch("ES256 verification requires an EC2 key")
  }
}

///|
fn symmetric_key(key : CoseKey) -> Bytes raise CoseError {
  match key {
    CoseKey::Sym(sym) => sym.k
    _ => raise AlgMismatch("this algorithm requires a symmetric key")
  }
}

///|
fn sign_with(
  alg : CoseAlg,
  key : CoseKey,
  tbs : Bytes,
) -> Bytes raise CoseError {
  match alg.normalize() {
    CoseAlg::EdDSA => @lib.ed25519_sign(ed25519_seed(key), tbs)
    CoseAlg::ES256 => @lib.ecdsa_p256_sign(p256_private(key), tbs)
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn verify_with(
  alg : CoseAlg,
  key : CoseKey,
  tbs : Bytes,
  signature : Bytes,
) -> Unit raise CoseError {
  let ok = match alg.normalize() {
    CoseAlg::EdDSA => @lib.ed25519_verify(ed25519_public(key), tbs, signature)
    CoseAlg::ES256 => @lib.ecdsa_p256_verify(p256_public(key), tbs, signature)
    other => raise UnsupportedAlg(other.name())
  }
  if !ok {
    raise VerificationFailed
  }
}

///|
fn mac_with(alg : CoseAlg, key : CoseKey, tbs : Bytes) -> Bytes raise CoseError {
  match alg.normalize() {
    CoseAlg::HMAC_256_256 => @lib.hmac_sha256(symmetric_key(key), tbs)
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn check_mac(
  alg : CoseAlg,
  key : CoseKey,
  tbs : Bytes,
  tag : Bytes,
) -> Unit raise CoseError {
  let expected = mac_with(alg, key, tbs)
  if !bytes_eq(expected, tag) {
    raise VerificationFailed
  }
}

///|
fn resolve_iv(prot : Header, unprot : Header) -> Bytes raise CoseError {
  match (prot.partial_iv, unprot.partial_iv) {
    (Some(_), _) | (_, Some(_)) =>
      if prot.iv is None && unprot.iv is None {
        raise BadStructure(
          "partial IV is carried but not expanded; provide a 12-byte IV",
        )
      }
    (None, None) => ()
  }
  match (prot.iv, unprot.iv) {
    (Some(left), Some(right)) =>
      if bytes_eq(left, right) {
        left
      } else {
        raise BadStructure("protected IV does not match unprotected IV")
      }
    (Some(iv), None) => iv
    (None, Some(iv)) => iv
    (None, None) => raise BadStructure("missing IV")
  }
}

///|
fn gcm_seal(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CoseError {
  if key.length() != 16 && key.length() != 32 {
    raise BadStructure("AES-GCM key must be 16 or 32 bytes")
  }
  if iv.length() != 12 {
    raise BadStructure("AES-GCM IV must be 12 bytes")
  }
  let boxed = @lib.aes_gcm_encrypt(plaintext, key, iv, aad)
  bytes_concat(boxed.ct, boxed.tag)
}

///|
fn gcm_open(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CoseError {
  if key.length() != 16 && key.length() != 32 {
    raise BadStructure("AES-GCM key must be 16 or 32 bytes")
  }
  if iv.length() != 12 {
    raise BadStructure("AES-GCM IV must be 12 bytes")
  }
  if ciphertext.length() < 16 {
    raise DecryptionFailed
  }
  let split = ciphertext.length() - 16
  let ct = bytes_slice(ciphertext, 0, split)
  let tag = bytes_slice(ciphertext, split, ciphertext.length())
  match @lib.aes_gcm_decrypt(ct, key, iv, aad, tag) {
    Ok(pt) => pt
    Err(_) => raise DecryptionFailed
  }
}
