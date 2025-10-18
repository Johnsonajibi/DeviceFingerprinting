#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Exposes the library version to C callers.
 */
char *get_library_version(void);

/**
 * Frees a C string that was allocated by Rust.
 */
void free_string(char *s);

/**
 * Calculates the SHA3-512 hash of a byte slice and returns it as a hex-encoded C string.
 * The caller is responsible for freeing the returned string.
 */
char *sha3_512_hex(const uint8_t *data, uintptr_t len);

/**
 * Retrieves CPU feature flags as a comma-separated C string.
 * The caller is responsible for freeing the returned string.
 */
char *get_cpu_features(void);
