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
  let raw = symmetric_key(key)
  match alg.normalize() {
    CoseAlg::HMAC_256_256 => @lib.hmac_sha256(raw, tbs)
    CoseAlg::HMAC_256_64 => bytes_slice(@lib.hmac_sha256(raw, tbs), 0, 8)
    CoseAlg::HMAC_384_384 => @lib.hmac_sha384(raw, tbs)
    CoseAlg::HMAC_512_512 => @lib.hmac_sha512(raw, tbs)
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
fn iv_size(alg : CoseAlg) -> Int32 raise CoseError {
  match alg.normalize() {
    CoseAlg::A128GCM
    | CoseAlg::A192GCM
    | CoseAlg::A256GCM
    | CoseAlg::ChaCha20Poly1305 => 12
    CoseAlg::AesCcm16_64_128
    | CoseAlg::AesCcm16_64_256
    | CoseAlg::AesCcm16_128_128
    | CoseAlg::AesCcm16_128_256 => 13
    CoseAlg::AesCcm64_64_128
    | CoseAlg::AesCcm64_64_256
    | CoseAlg::AesCcm64_128_128
    | CoseAlg::AesCcm64_128_256 => 7
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn partial_iv(prot : Header, unprot : Header) -> Bytes? raise CoseError {
  match (prot.partial_iv, unprot.partial_iv) {
    (Some(left), Some(right)) =>
      if bytes_eq(left, right) {
        Some(left)
      } else {
        raise BadStructure(
          "protected partial IV does not match unprotected partial IV",
        )
      }
    (Some(part), None) => Some(part)
    (None, Some(part)) => Some(part)
    (None, None) => None
  }
}

///|
/// Build the AEAD nonce. A full IV is used as-is. A partial IV is XORed onto
/// the right-hand side of the key's Base IV, or onto zeros when the key has
/// no Base IV (RFC 9052 / RFC 9053).
fn resolve_iv(
  alg : CoseAlg,
  prot : Header,
  unprot : Header,
  base_iv : Bytes?,
) -> Bytes raise CoseError {
  let size = iv_size(alg)
  match (prot.iv, unprot.iv) {
    (Some(left), Some(right)) => {
      if !bytes_eq(left, right) {
        raise BadStructure("protected IV does not match unprotected IV")
      }
      require_len(left, size, "IV")
      return left
    }
    (Some(iv), None) | (None, Some(iv)) => {
      require_len(iv, size, "IV")
      return iv
    }
    (None, None) => ()
  }
  match partial_iv(prot, unprot) {
    None => raise BadStructure("missing IV")
    Some(part) => {
      if part.length() == 0 || part.length() > size {
        raise BadStructure("partial IV length is outside the IV size")
      }
      let base = match base_iv {
        Some(b) => {
          require_len(b, size, "Base IV")
          b
        }
        None => Bytes::make(size, b'\x00')
      }
      let out = Array::make(size, b'\x00')
      for i = 0; i < size; i = i + 1 {
        out[i] = base[i]
      }
      let start = size - part.length()
      for i = 0; i < part.length(); i = i + 1 {
        let at = start + i
        out[at] = (out[at].to_int() ^ part[i].to_int()).to_byte()
      }
      Bytes::from_array(out)
    }
  }
}

///|
fn gcm_seal(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CoseError {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    raise BadStructure("AES-GCM key must be 16, 24, or 32 bytes")
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
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    raise BadStructure("AES-GCM key must be 16, 24, or 32 bytes")
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

///|
fn ccm_tag_len(alg : CoseAlg) -> Int32 {
  match alg.normalize() {
    CoseAlg::AesCcm16_64_128
    | CoseAlg::AesCcm16_64_256
    | CoseAlg::AesCcm64_64_128
    | CoseAlg::AesCcm64_64_256 => 8
    _ => 16
  }
}

///|
fn content_key_len(alg : CoseAlg) -> Int32 raise CoseError {
  match alg.normalize() {
    CoseAlg::A128GCM
    | CoseAlg::AesCcm16_64_128
    | CoseAlg::AesCcm64_64_128
    | CoseAlg::AesCcm16_128_128
    | CoseAlg::AesCcm64_128_128 => 16
    CoseAlg::A192GCM => 24
    CoseAlg::A256GCM
    | CoseAlg::ChaCha20Poly1305
    | CoseAlg::AesCcm16_64_256
    | CoseAlg::AesCcm64_64_256
    | CoseAlg::AesCcm16_128_256
    | CoseAlg::AesCcm64_128_256 => 32
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn content_seal(
  alg : CoseAlg,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CoseError {
  let normalized = alg.normalize()
  require_len(key, content_key_len(normalized), "content key")
  require_len(iv, iv_size(normalized), "IV")
  match normalized {
    CoseAlg::A128GCM | CoseAlg::A192GCM | CoseAlg::A256GCM =>
      gcm_seal(key, iv, aad, plaintext)
    CoseAlg::ChaCha20Poly1305 =>
      @lib.chacha20_poly1305_encrypt(key, iv, aad, plaintext)
    CoseAlg::AesCcm16_64_128
    | CoseAlg::AesCcm16_64_256
    | CoseAlg::AesCcm64_64_128
    | CoseAlg::AesCcm64_64_256
    | CoseAlg::AesCcm16_128_128
    | CoseAlg::AesCcm16_128_256
    | CoseAlg::AesCcm64_128_128
    | CoseAlg::AesCcm64_128_256 =>
      @lib.aes_ccm_encrypt(plaintext, key, iv, aad, ccm_tag_len(normalized))
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn content_open(
  alg : CoseAlg,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CoseError {
  let normalized = alg.normalize()
  require_len(key, content_key_len(normalized), "content key")
  require_len(iv, iv_size(normalized), "IV")
  match normalized {
    CoseAlg::A128GCM | CoseAlg::A192GCM | CoseAlg::A256GCM =>
      gcm_open(key, iv, aad, ciphertext)
    CoseAlg::ChaCha20Poly1305 =>
      match @lib.chacha20_poly1305_decrypt_or(key, iv, aad, ciphertext) {
        Ok(pt) => pt
        Err(_) => raise DecryptionFailed
      }
    CoseAlg::AesCcm16_64_128
    | CoseAlg::AesCcm16_64_256
    | CoseAlg::AesCcm64_64_128
    | CoseAlg::AesCcm64_64_256
    | CoseAlg::AesCcm16_128_128
    | CoseAlg::AesCcm16_128_256
    | CoseAlg::AesCcm64_128_128
    | CoseAlg::AesCcm64_128_256 =>
      match
        @lib.aes_ccm_decrypt_or(
          ciphertext,
          key,
          iv,
          aad,
          ccm_tag_len(normalized),
        ) {
        Ok(pt) => pt
        Err(_) => raise DecryptionFailed
      }
    other => raise UnsupportedAlg(other.name())
  }
}

///|
fn kw_wrap(alg : CoseAlg, kek : Bytes, cek : Bytes) -> Bytes raise CoseError {
  let want = match alg.normalize() {
    CoseAlg::A128KW => 16
    CoseAlg::A192KW => 24
    CoseAlg::A256KW => 32
    other => raise UnsupportedAlg(other.name())
  }
  require_len(kek, want, alg.name())
  if cek.length() == 0 || cek.length() % 8 != 0 {
    raise BadStructure("content key length must be a non-zero multiple of 8")
  }
  @lib.aes_kw_wrap(kek, cek)
}

///|
fn kw_unwrap(
  alg : CoseAlg,
  kek : Bytes,
  wrapped : Bytes,
) -> Bytes raise CoseError {
  let want = match alg.normalize() {
    CoseAlg::A128KW => 16
    CoseAlg::A192KW => 24
    CoseAlg::A256KW => 32
    other => raise UnsupportedAlg(other.name())
  }
  require_len(kek, want, alg.name())
  match @lib.aes_kw_unwrap(kek, wrapped) {
    Ok(cek) => cek
    Err(_) => raise DecryptionFailed
  }
}
