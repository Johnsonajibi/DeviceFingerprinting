
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic;
use sha3::{Digest, Sha3_512};
use hex;
use cpufeatures;

/// A utility function to convert a Rust string into a C-compatible, heap-allocated string.
/// The caller is responsible for freeing this memory using `free_string`.
fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

/// Exposes the library version to C callers.
#[no_mangle]
pub extern "C" fn get_library_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION").to_string())
}

/// Frees a C string that was allocated by Rust.
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// Calculates the SHA3-512 hash of a byte slice and returns it as a hex-encoded C string.
/// The caller is responsible for freeing the returned string.
#[no_mangle]
pub extern "C" fn sha3_512_hex(data: *const u8, len: usize) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        if data.is_null() {
            return to_c_string("".to_string());
        }
        let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
        
        let mut hasher = Sha3_512::new();
        hasher.update(data_slice);
        let hash_result = hasher.finalize();
        
        to_c_string(hex::encode(hash_result))
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Retrieves CPU feature flags as a comma-separated C string.
/// The caller is responsible for freeing the returned string.
#[no_mangle]
pub extern "C" fn get_cpu_features() -> *mut c_char {
    let mut features = Vec::new();

    // On x86/x86_64, use the is_x86_feature_detected macro
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") { features.push("avx2"); }
        if is_x86_feature_detected!("avx") { features.push("avx"); }
        if is_x86_feature_detected!("sse4.2") { features.push("sse4.2"); }
        if is_x86_feature_detected!("sse4.1") { features.push("sse4.1"); }
        if is_x86_feature_detected!("ssse3") { features.push("ssse3"); }
        if is_x86_feature_detected!("sse3") { features.push("sse3"); }
        if is_x86_feature_detected!("sse2") { features.push("sse2"); }
        if is_x86_feature_detected!("sse") { features.push("sse"); }
        if is_x86_feature_detected!("aes") { features.push("aes"); }
        if is_x86_feature_detected!("pclmulqdq") { features.push("pclmulqdq"); }
        if is_x86_feature_detected!("rdrand") { features.push("rdrand"); }
        if is_x86_feature_detected!("rdseed") { features.push("rdseed"); }
        if is_x86_feature_detected!("sha") { features.push("sha"); }
    }

    to_c_string(features.join(","))
}
