//! ML-KEM unified API
//!
//! This module provides a unified high-level API for ML-KEM (Module-Lattice-Based
//! Key Encapsulation Mechanism) that works with both OpenSSL 3.5+ and BoringSSL backends.
//!
//! # Example
//!
//! ```no_run
//! use openssl::ml_kem::{MlKemKeyPair, Variant};
//!
//! // Generate a new key pair
//! let keypair = MlKemKeyPair::generate(Variant::MlKem768).unwrap();
//!
//! // In a real scenario, you would:
//! // 1. Encapsulate to get ciphertext + shared secret
//! // 2. Decapsulate the ciphertext to recover the shared secret
//! ```

use crate::error::ErrorStack;

pub use crate::pkey_ml_kem::Variant;

#[cfg(ossl350)]
use crate::{pkey::PKey, pkey_ctx::PkeyCtx};
#[cfg(ossl350)]
use foreign_types::ForeignType;

#[cfg(boringssl)]
use crate::pkey_ml_kem::{PKeyMlKemParams, Private};

/// An ML-KEM key pair that can perform key encapsulation.
pub struct MlKemKeyPair {
    variant: Variant,
    #[cfg(ossl350)]
    pkey: PKey<crate::pkey::Private>,
    #[cfg(boringssl)]
    params: PKeyMlKemParams<Private>,
}

impl MlKemKeyPair {
    /// Generate a new ML-KEM key pair.
    ///
    /// Note: ML-KEM-512 is not supported by BoringSSL.
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack> {
        #[cfg(ossl350)]
        {
            let pkey = PKey::generate_ml_kem(variant)?;
            Ok(MlKemKeyPair { variant, pkey })
        }

        #[cfg(boringssl)]
        {
            let params = PKeyMlKemParams::<Private>::generate(variant)?;
            Ok(MlKemKeyPair { variant, params })
        }
    }

    /// Create an ML-KEM key pair from a seed.
    ///
    /// The seed must be exactly 64 bytes.
    ///
    /// Note: ML-KEM-512 is not supported by BoringSSL.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack> {
        #[cfg(ossl350)]
        {
            use crate::ossl_param::OsslParamBuilder;
            use std::ffi::CStr;

            const OSSL_PKEY_PARAM_SEED: &CStr =
                unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };

            let mut bld = OsslParamBuilder::new()?;
            bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
            let mut ctx = PkeyCtx::new_from_name(None, variant.as_str(), None)?;
            ctx.fromdata_init()?;
            let params = bld.to_param()?;
            unsafe {
                let evp = crate::cvt_p(ffi::EVP_PKEY_new())?;
                let pkey = PKey::from_ptr(evp);
                crate::cvt(ffi::EVP_PKEY_fromdata(
                    ctx.as_ptr(),
                    &mut pkey.as_ptr(),
                    ffi::EVP_PKEY_KEYPAIR,
                    params.as_ptr(),
                ))?;
                Ok(MlKemKeyPair { variant, pkey })
            }
        }

        #[cfg(boringssl)]
        {
            let params = PKeyMlKemParams::<Private>::from_seed(variant, seed)?;
            Ok(MlKemKeyPair { variant, params })
        }
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            let mut ctx = PkeyCtx::new(&self.pkey)?;
            ctx.decapsulate_init()?;
            let mut secret = vec![];
            ctx.decapsulate_to_vec(ciphertext, &mut secret)?;
            Ok(secret)
        }

        #[cfg(boringssl)]
        {
            self.params.decapsulate(ciphertext)
        }
    }

    /// Encapsulate to generate a ciphertext and shared secret.
    ///
    /// Returns a tuple of (ciphertext, shared_secret).
    ///
    /// Note: For BoringSSL, this requires public key operations which are not
    /// yet fully implemented.
    #[cfg(ossl350)]
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let mut ctx = PkeyCtx::new(&self.pkey)?;
        ctx.encapsulate_init()?;
        let mut ciphertext = vec![];
        let mut secret = vec![];
        ctx.encapsulate_to_vec(&mut ciphertext, &mut secret)?;
        Ok((ciphertext, secret))
    }

    /// Encapsulate to generate a ciphertext and shared secret.
    ///
    /// Note: Not yet implemented for BoringSSL backend.
    #[cfg(boringssl)]
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        // TODO: Implement encapsulation for BoringSSL
        // Would need to implement encapsulate() on PKeyMlKemParams<Public>
        Err(ErrorStack::get())
    }

    /// Get the public key bytes in encoded form.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            self.pkey.raw_public_key()
        }

        #[cfg(boringssl)]
        {
            Ok(self.params.public_key()?.to_vec())
        }
    }

    /// Get the private key seed.
    pub fn private_key_seed(&self) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            let params = self.pkey.ml_kem(self.variant)?.unwrap();
            params.private_key_seed().map(|s| s.to_vec())
        }

        #[cfg(boringssl)]
        {
            self.params.private_key_seed().map(|s| s.to_vec())
        }
    }

    /// Get the variant of this key pair.
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let keypair = MlKemKeyPair::generate(Variant::MlKem768).unwrap();
        let pub_key = keypair.public_key_bytes().unwrap();
        assert_eq!(pub_key.len(), Variant::MlKem768.public_key_bytes());
    }

    #[test]
    #[cfg(boringssl)]
    fn test_generate_512_fails_on_boringssl() {
        // BoringSSL doesn't support ML-KEM-512
        let result = MlKemKeyPair::generate(Variant::MlKem512);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0x42u8; 64];
        let keypair1 = MlKemKeyPair::from_seed(Variant::MlKem768, &seed).unwrap();
        let keypair2 = MlKemKeyPair::from_seed(Variant::MlKem768, &seed).unwrap();

        // Same seed should produce same public key
        assert_eq!(
            keypair1.public_key_bytes().unwrap(),
            keypair2.public_key_bytes().unwrap()
        );
    }

    #[test]
    #[cfg(ossl350)]
    fn test_encapsulate_decapsulate() {
        let keypair = MlKemKeyPair::generate(Variant::MlKem1024).unwrap();

        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, secret1) = keypair.encapsulate().unwrap();

        // Decapsulate to recover shared secret
        let secret2 = keypair.decapsulate(&ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32); // ML-KEM shared secret is always 32 bytes
    }
}
