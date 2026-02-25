#![allow(clippy::inconsistent_digit_grouping, clippy::unusual_byte_groupings)]

use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl300)");
    println!("cargo:rustc-check-cfg=cfg(boringssl)");
    println!("cargo:rustc-check-cfg=cfg(awslc)");

    // Propagate boringssl cfg from openssl-sys
    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=boringssl");
    }

    // Propagate awslc cfg from openssl-sys
    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=awslc");
    }

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x3_00_00_00_0 {
            println!("cargo:rustc-cfg=ossl300");
        }
    }
}
