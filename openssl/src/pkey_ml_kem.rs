//! Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! ML-KEM is a Key-Encapsulation Mechanism that is believed to be
//! secure against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 203].
//!
//! Note: BoringSSL only supports ML-KEM-768 and ML-KEM-1024 (not ML-KEM-512).
//!
//! [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final

#[cfg(boringssl)]
use crate::cvt;
use crate::error::ErrorStack;
#[cfg(ossl350)]
use crate::ossl_param::OsslParamArray;
#[cfg(ossl350)]
use std::ffi::CStr;
use std::marker::PhantomData;

// Re-export type markers
#[cfg(ossl350)]
pub use crate::pkey::Private;

#[cfg(boringssl)]
/// Marker type for private keys
pub enum Private {}

// OpenSSL-specific constants
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_SEED: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_PUB_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pub\0") };
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_PRIV_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"priv\0") };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    #[cfg(boringssl)]
    fn public_key_bytes(&self) -> usize {
        match self {
            Variant::MlKem512 => panic!("ML-KEM-512 not supported by BoringSSL"),
            Variant::MlKem768 => ffi::mlkem::MLKEM768_PUBLIC_KEY_BYTES,
            Variant::MlKem1024 => ffi::mlkem::MLKEM1024_PUBLIC_KEY_BYTES,
        }
    }
}

// OpenSSL implementation
#[cfg(ossl350)]
pub struct PKeyMlKemParams<T> {
    params: OsslParamArray,
    _m: PhantomData<T>,
}

// BoringSSL implementation
#[cfg(boringssl)]
pub struct PKeyMlKemParams<T> {
    variant: Variant,
    public_key_bytes: Vec<u8>,
    seed: Option<[u8; ffi::mlkem::MLKEM_SEED_BYTES]>,
    _m: PhantomData<T>,
}

#[cfg(ossl350)]
impl<T> PKeyMlKemParams<T> {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PUB_KEY)
    }
}

#[cfg(ossl350)]
impl PKeyMlKemParams<Private> {
    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_SEED)
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PRIV_KEY)
    }
}

#[cfg(boringssl)]
impl<T> PKeyMlKemParams<T> {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        Ok(&self.public_key_bytes)
    }
}

#[cfg(boringssl)]
impl PKeyMlKemParams<Private> {
    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.seed
            .as_ref()
            .map(|s| s.as_slice())
            .ok_or_else(|| ErrorStack::get())
    }

    /// Generate a new keypair.
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack> {
        if variant == Variant::MlKem512 {
            // BoringSSL doesn't support ML-KEM-512
            return Err(ErrorStack::get());
        }

        let mut public_key_bytes = vec![0u8; variant.public_key_bytes()];
        let mut seed = [0u8; ffi::mlkem::MLKEM_SEED_BYTES];

        match variant {
            Variant::MlKem512 => unreachable!(),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    ffi::mlkem::MLKEM768_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    );
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    ffi::mlkem::MLKEM1024_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    );
                }
            }
        }

        Ok(PKeyMlKemParams {
            variant,
            public_key_bytes,
            seed: Some(seed),
            _m: PhantomData,
        })
    }

    /// Create from seed.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack> {
        if variant == Variant::MlKem512 {
            return Err(ErrorStack::get());
        }
        if seed.len() != ffi::mlkem::MLKEM_SEED_BYTES {
            return Err(ErrorStack::get());
        }

        let public_key_bytes = vec![0u8; variant.public_key_bytes()];

        match variant {
            Variant::MlKem512 => unreachable!(),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM768_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM768_public_key {
                        opaque: ffi::mlkem::MLKEM768_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM768_public_from_private(&mut pub_key, &priv_key);
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM1024_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM1024_public_key {
                        opaque: ffi::mlkem::MLKEM1024_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM1024_public_from_private(&mut pub_key, &priv_key);
                }
            }
        }

        let mut seed_arr = [0u8; ffi::mlkem::MLKEM_SEED_BYTES];
        seed_arr.copy_from_slice(seed);

        Ok(PKeyMlKemParams {
            variant,
            public_key_bytes,
            seed: Some(seed_arr),
            _m: PhantomData,
        })
    }

    /// Decapsulate a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let seed = self.seed.as_ref().ok_or_else(|| ErrorStack::get())?;
        let mut shared_secret = vec![0u8; ffi::mlkem::MLKEM_SHARED_SECRET_BYTES];

        match self.variant {
            Variant::MlKem512 => return Err(ErrorStack::get()),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM768_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mlkem::MLKEM768_decap(
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &priv_key,
                    ))?;
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM1024_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mlkem::MLKEM1024_decap(
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &priv_key,
                    ))?;
                }
            }
        }

        Ok(shared_secret)
    }
}
