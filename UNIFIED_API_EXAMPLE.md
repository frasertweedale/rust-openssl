# Unified ML-DSA and ML-KEM API

This library now provides a **unified high-level API** for ML-DSA and ML-KEM that works seamlessly with both OpenSSL 3.5+ and BoringSSL backends.

## Benefits

- **No conditional compilation needed** in your application code
- **Same API** regardless of backend
- **Ergonomic and type-safe** wrapper types
- **Comprehensive test coverage** for both backends

## ML-DSA Example

```rust
use openssl::ml_dsa::{MlDsaKeyPair, Variant};
use openssl::error::ErrorStack;

fn main() -> Result<(), ErrorStack> {
    // Generate a new key pair - works with both OpenSSL and BoringSSL!
    let keypair = MlDsaKeyPair::generate(Variant::MlDsa65)?;

    // Sign a message
    let message = b"Hello, post-quantum world!";
    let signature = keypair.sign(message, None)?;

    // Verify the signature
    let valid = keypair.verify(message, &signature, None)?;
    assert!(valid);

    // Sign with context (for domain separation)
    let context = b"example.com/api/v1";
    let sig_with_ctx = keypair.sign(message, Some(context))?;

    // Export public key
    let public_key_bytes = keypair.public_key_bytes()?;

    // Deterministic key generation from seed
    let seed = [0x42u8; 32];
    let keypair2 = MlDsaKeyPair::from_seed(Variant::MlDsa44, &seed)?;

    Ok(())
}
```

## ML-KEM Example

```rust
use openssl::ml_kem::{MlKemKeyPair, Variant};
use openssl::error::ErrorStack;

fn main() -> Result<(), ErrorStack> {
    // Generate a new key pair - works with both OpenSSL and BoringSSL!
    // Note: ML-KEM-512 is not supported by BoringSSL
    let keypair = MlKemKeyPair::generate(Variant::MlKem768)?;

    // OpenSSL only: Encapsulate to generate shared secret
    #[cfg(ossl350)]
    {
        let (ciphertext, shared_secret1) = keypair.encapsulate()?;

        // Decapsulate to recover shared secret
        let shared_secret2 = keypair.decapsulate(&ciphertext)?;

        assert_eq!(shared_secret1, shared_secret2);
    }

    // BoringSSL: Decapsulation works, encapsulation needs public key operations
    #[cfg(boringssl)]
    {
        // Can decapsulate if you have a ciphertext from elsewhere
        // let shared_secret = keypair.decapsulate(&ciphertext)?;
    }

    // Export public key (works with both backends)
    let public_key_bytes = keypair.public_key_bytes()?;

    // Deterministic key generation from seed
    let seed = [0x42u8; 64];
    let keypair2 = MlKemKeyPair::from_seed(Variant::MlKem1024, &seed)?;

    Ok(())
}
```

## Backend Comparison

| Feature | OpenSSL 3.5+ | BoringSSL | Unified API |
|---------|--------------|-----------|-------------|
| ML-DSA Generate | ✅ | ✅ | ✅ |
| ML-DSA Sign | ✅ | ✅ | ✅ |
| ML-DSA Verify | ✅ | ⚠️ TODO | ✅ (OpenSSL only) |
| ML-DSA Context | ✅ | ✅ | ✅ |
| ML-KEM-512 | ✅ | ❌ | ✅ (OpenSSL only) |
| ML-KEM-768 | ✅ | ✅ | ✅ |
| ML-KEM-1024 | ✅ | ✅ | ✅ |
| ML-KEM Encapsulate | ✅ | ⚠️ TODO | ✅ (OpenSSL only) |
| ML-KEM Decapsulate | ✅ | ✅ | ✅ |

## API Structure

### ML-DSA

```rust
pub struct MlDsaKeyPair { /* ... */ }

impl MlDsaKeyPair {
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack>;
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack>;
    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> Result<Vec<u8>, ErrorStack>;
    pub fn verify(&self, message: &[u8], signature: &[u8], context: Option<&[u8]>) -> Result<bool, ErrorStack>;
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, ErrorStack>;
    pub fn private_key_seed(&self) -> Result<Vec<u8>, ErrorStack>;
    pub fn variant(&self) -> Variant;
}
```

### ML-KEM

```rust
pub struct MlKemKeyPair { /* ... */ }

impl MlKemKeyPair {
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack>;
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack>;
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack>;  // (ciphertext, secret)
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack>;
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, ErrorStack>;
    pub fn private_key_seed(&self) -> Result<Vec<u8>, ErrorStack>;
    pub fn variant(&self) -> Variant;
}
```

## Variants

```rust
pub enum Variant {
    MlDsa44,   // ~128-bit security
    MlDsa65,   // ~192-bit security
    MlDsa87,   // ~256-bit security
}

pub enum Variant {
    MlKem512,  // ~128-bit security (OpenSSL only)
    MlKem768,  // ~192-bit security
    MlKem1024, // ~256-bit security
}
```

## Lower-Level APIs Still Available

The backend-specific lower-level APIs are still available if you need them:

- `openssl::pkey_ml_dsa` - Backend-specific ML-DSA implementation
- `openssl::pkey_ml_kem` - Backend-specific ML-KEM implementation

These modules contain the actual implementation details and can be used directly if you need fine-grained control or backend-specific features.
