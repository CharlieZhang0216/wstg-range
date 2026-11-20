/*
 * Acme telemetry shim - lazily loaded second module. Shipped as telemetry.bin
 * (no .wasm extension) so module discovery has to follow the JS, not the URL.
 */

static const char collector[] = "http://grpc:50051/lab.Inventory/ListItems";
static const char build_tag[] = "telemetry-2.3.1-internal";

static long ticks;

long telemetry_tick(void) {
    ticks += 1;
    return ticks;
}

const char *telemetry_collector(void) {
    return collector;
}

const char *telemetry_build_tag(void) {
    return build_tag;
}