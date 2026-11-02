///|
/// Failures produced by COSE encode, decode, and cryptographic operations.
pub(all) suberror CoseError {
  BadStructure(String)
  UnsupportedAlg(String)
  AlgMismatch(String)
  VerificationFailed
  DecryptionFailed
  MalformedCbor(String)
} derive(Eq, Debug)

///|
pub extend CoseError with Eq::{equal}

///|
#deprecated("Use `!=` instead", skip_current_package=true)
#doc(hidden)
pub extend CoseError with Eq::{not_equal}

///|
pub impl Show for CoseError with fn output(self, logger) {
  logger.write_string(
    match self {
      BadStructure(msg) => "bad structure: \{msg}"
      UnsupportedAlg(msg) => "unsupported alg: \{msg}"
      AlgMismatch(msg) => "alg mismatch: \{msg}"
      VerificationFailed => "verification failed"
      DecryptionFailed => "decryption failed"
      MalformedCbor(msg) => "malformed cbor: \{msg}"
    },
  )
}
