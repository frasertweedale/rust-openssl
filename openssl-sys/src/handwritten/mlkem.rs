use super::super::*;
use libc::*;

// ML-KEM constants
pub const MLKEM_SEED_BYTES: usize = 64;
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;

// ML-KEM-768
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

#[repr(C)]
pub struct MLKEM768_public_key {
    pub opaque: MLKEM768_public_key_union,
}

#[repr(C)]
pub union MLKEM768_public_key_union {
    pub bytes: [u8; 512 * (3 + 9) + 32 + 32],
    pub alignment: u16,
}

#[repr(C)]
pub struct MLKEM768_private_key {
    pub opaque: MLKEM768_private_key_union,
}

#[repr(C)]
pub union MLKEM768_private_key_union {
    pub bytes: [u8; 512 * (3 + 3 + 9) + 32 + 32 + 32],
    pub alignment: u16,
}

// ML-KEM-1024
pub const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;

#[repr(C)]
pub struct MLKEM1024_public_key {
    pub opaque: MLKEM1024_public_key_union,
}

#[repr(C)]
pub union MLKEM1024_public_key_union {
    pub bytes: [u8; 512 * (4 + 16) + 32 + 32],
    pub alignment: u16,
}

#[repr(C)]
pub struct MLKEM1024_private_key {
    pub opaque: MLKEM1024_private_key_union,
}

#[repr(C)]
pub union MLKEM1024_private_key_union {
    pub bytes: [u8; 512 * (4 + 4 + 16) + 32 + 32 + 32],
    pub alignment: u16,
}

extern "C" {
    // ML-KEM-768 functions
    pub fn MLKEM768_generate_key(
        out_encoded_public_key: *mut u8,
        optional_out_seed: *mut u8,
        out_private_key: *mut MLKEM768_private_key,
    );

    pub fn MLKEM768_private_key_from_seed(
        out_private_key: *mut MLKEM768_private_key,
        seed: *const u8,
        seed_len: size_t,
    ) -> c_int;

    pub fn MLKEM768_public_from_private(
        out_public_key: *mut MLKEM768_public_key,
        private_key: *const MLKEM768_private_key,
    );

    pub fn MLKEM768_encap(
        out_ciphertext: *mut u8,
        out_shared_secret: *mut u8,
        public_key: *const MLKEM768_public_key,
    );

    pub fn MLKEM768_decap(
        out_shared_secret: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: size_t,
        private_key: *const MLKEM768_private_key,
    ) -> c_int;

    pub fn MLKEM768_marshal_public_key(
        out: *mut CBB,
        public_key: *const MLKEM768_public_key,
    ) -> c_int;

    pub fn MLKEM768_parse_public_key(
        out_public_key: *mut MLKEM768_public_key,
        input: *mut CBS,
    ) -> c_int;

    // ML-KEM-1024 functions
    pub fn MLKEM1024_generate_key(
        out_encoded_public_key: *mut u8,
        optional_out_seed: *mut u8,
        out_private_key: *mut MLKEM1024_private_key,
    );

    pub fn MLKEM1024_private_key_from_seed(
        out_private_key: *mut MLKEM1024_private_key,
        seed: *const u8,
        seed_len: size_t,
    ) -> c_int;

    pub fn MLKEM1024_public_from_private(
        out_public_key: *mut MLKEM1024_public_key,
        private_key: *const MLKEM1024_private_key,
    );

    pub fn MLKEM1024_encap(
        out_ciphertext: *mut u8,
        out_shared_secret: *mut u8,
        public_key: *const MLKEM1024_public_key,
    );

    pub fn MLKEM1024_decap(
        out_shared_secret: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: size_t,
        private_key: *const MLKEM1024_private_key,
    ) -> c_int;

    pub fn MLKEM1024_marshal_public_key(
        out: *mut CBB,
        public_key: *const MLKEM1024_public_key,
    ) -> c_int;

    pub fn MLKEM1024_parse_public_key(
        out_public_key: *mut MLKEM1024_public_key,
        input: *mut CBS,
    ) -> c_int;
}
