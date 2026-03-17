use super::super::*;
use libc::*;

// ML-DSA constants
pub const MLDSA_SEED_BYTES: usize = 32;
pub const MLDSA_MU_BYTES: usize = 64;

// ML-DSA-44
pub const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
pub const MLDSA44_SIGNATURE_BYTES: usize = 2420;

#[repr(C)]
pub struct MLDSA44_private_key {
    pub opaque: MLDSA44_private_key_union,
}

#[repr(C)]
pub union MLDSA44_private_key_union {
    pub bytes: [u8; (32 + 64 + 256 * 4 * 4) + 32 + 256 * 4 * (4 + 4 + 4)],
    pub alignment: u32,
}

#[repr(C)]
pub struct MLDSA44_public_key {
    pub opaque: MLDSA44_public_key_union,
}

#[repr(C)]
pub union MLDSA44_public_key_union {
    pub bytes: [u8; 32 + 64 + 256 * 4 * 4],
    pub alignment: u32,
}

// ML-DSA-65
pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;

#[repr(C)]
pub struct MLDSA65_private_key {
    pub opaque: MLDSA65_private_key_union,
}

#[repr(C)]
pub union MLDSA65_private_key_union {
    pub bytes: [u8; (32 + 64 + 256 * 4 * 6) + 32 + 256 * 4 * (5 + 6 + 6)],
    pub alignment: u32,
}

#[repr(C)]
pub struct MLDSA65_public_key {
    pub opaque: MLDSA65_public_key_union,
}

#[repr(C)]
pub union MLDSA65_public_key_union {
    pub bytes: [u8; 32 + 64 + 256 * 4 * 6],
    pub alignment: u32,
}

// ML-DSA-87
pub const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
pub const MLDSA87_SIGNATURE_BYTES: usize = 4627;

#[repr(C)]
pub struct MLDSA87_private_key {
    pub opaque: MLDSA87_private_key_union,
}

#[repr(C)]
pub union MLDSA87_private_key_union {
    pub bytes: [u8; (32 + 64 + 256 * 4 * 8) + 32 + 256 * 4 * (7 + 8 + 8)],
    pub alignment: u32,
}

#[repr(C)]
pub struct MLDSA87_public_key {
    pub opaque: MLDSA87_public_key_union,
}

#[repr(C)]
pub union MLDSA87_public_key_union {
    pub bytes: [u8; 32 + 64 + 256 * 4 * 8],
    pub alignment: u32,
}

extern "C" {
    // ML-DSA-44 functions
    pub fn MLDSA44_generate_key(
        out_encoded_public_key: *mut u8,
        out_seed: *mut u8,
        out_private_key: *mut MLDSA44_private_key,
    ) -> c_int;

    pub fn MLDSA44_private_key_from_seed(
        out_private_key: *mut MLDSA44_private_key,
        seed: *const u8,
        seed_len: size_t,
    ) -> c_int;

    pub fn MLDSA44_public_from_private(
        out_public_key: *mut MLDSA44_public_key,
        private_key: *const MLDSA44_private_key,
    ) -> c_int;

    pub fn MLDSA44_sign(
        out_encoded_signature: *mut u8,
        private_key: *const MLDSA44_private_key,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;

    pub fn MLDSA44_verify(
        public_key: *const MLDSA44_public_key,
        signature: *const u8,
        signature_len: size_t,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;

    // ML-DSA-65 functions
    pub fn MLDSA65_generate_key(
        out_encoded_public_key: *mut u8,
        out_seed: *mut u8,
        out_private_key: *mut MLDSA65_private_key,
    ) -> c_int;

    pub fn MLDSA65_private_key_from_seed(
        out_private_key: *mut MLDSA65_private_key,
        seed: *const u8,
        seed_len: size_t,
    ) -> c_int;

    pub fn MLDSA65_public_from_private(
        out_public_key: *mut MLDSA65_public_key,
        private_key: *const MLDSA65_private_key,
    ) -> c_int;

    pub fn MLDSA65_sign(
        out_encoded_signature: *mut u8,
        private_key: *const MLDSA65_private_key,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;

    pub fn MLDSA65_verify(
        public_key: *const MLDSA65_public_key,
        signature: *const u8,
        signature_len: size_t,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;

    // ML-DSA-87 functions
    pub fn MLDSA87_generate_key(
        out_encoded_public_key: *mut u8,
        out_seed: *mut u8,
        out_private_key: *mut MLDSA87_private_key,
    ) -> c_int;

    pub fn MLDSA87_private_key_from_seed(
        out_private_key: *mut MLDSA87_private_key,
        seed: *const u8,
        seed_len: size_t,
    ) -> c_int;

    pub fn MLDSA87_public_from_private(
        out_public_key: *mut MLDSA87_public_key,
        private_key: *const MLDSA87_private_key,
    ) -> c_int;

    pub fn MLDSA87_sign(
        out_encoded_signature: *mut u8,
        private_key: *const MLDSA87_private_key,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;

    pub fn MLDSA87_verify(
        public_key: *const MLDSA87_public_key,
        signature: *const u8,
        signature_len: size_t,
        msg: *const u8,
        msg_len: size_t,
        context: *const u8,
        context_len: size_t,
    ) -> c_int;
}
