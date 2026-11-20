/*
 * Acme license validator - compiled to WebAssembly (freestanding, no libc).
 * INTERNAL NOTE: do not ship this source or debug builds to production.
 * (Both happen anyway - that is the WSTG-WASM-01 training point.)
 */

static const char api_key[] = "ak_wasm_9d41f0aa77c24e0bb1e6f3c2d8a45b17";
static const char internal_url[] = "http://internal:8080/latest/secret";
static const char admin_path[] = "/api/admin/users";
static const char build_flag[] = "WSTG-M10{wasm_never_hides_secrets}";

/* exported: internal helper names survive in the export + name sections */
int internal_license_checksum(int seed) {
    int acc = seed;
    for (int i = 0; i < 8; i++) {
        acc = (acc * 31) ^ (acc >> 3);
    }
    return acc & 0x7fffffff;
}

int validate_license(const char *input, int len) {
    int sum = 7;
    for (int i = 0; i < len; i++) {
        sum = (sum + input[i] * (i + 1)) & 0xffff;
    }
    return (sum % 97) == 23;
}

int decode_key_byte(int x) {
    return x ^ 0x5a;
}

const char *get_api_key(void) {
    return api_key;
}

const char *get_internal_url(void) {
    return internal_url;
}

const char *get_admin_path(void) {
    return admin_path;
}

const char *get_build_flag(void) {
    return build_flag;
}