# Stage 1: build the WebAssembly modules from C with clang + wasm-ld.
# -g keeps DWARF (.debug_*) and the `name` custom section; --export-dynamic
# keeps internal function names in the export section. Nothing is stripped.
FROM alpine:3.20 AS wasmbuild
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
RUN apk add --no-cache clang lld
WORKDIR /src
COPY src/ .
RUN clang --target=wasm32 -O1 -g -nostdlib -fvisibility=default \
      -Wl,--no-entry -Wl,--allow-undefined \
      -Wl,--export=validate_license -Wl,--export=internal_license_checksum \
      -Wl,--export=decode_key_byte -Wl,--export=get_api_key \
      -Wl,--export=get_internal_url -Wl,--export=get_admin_path \
      -Wl,--export=get_build_flag \
      -o license.wasm license.c \
 && clang --target=wasm32 -O1 -g -nostdlib -fvisibility=default \
      -Wl,--no-entry -Wl,--allow-undefined \
      -Wl,--export=telemetry_tick -Wl,--export=telemetry_collector \
      -Wl,--export=telemetry_build_tag \
      -o telemetry.bin telemetry.c

# Stage 2: static portal + reverse proxy. The original C source is shipped
# alongside the modules (the "leaked source" finding of WSTG-WASM-01).
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
COPY --from=wasmbuild /src/license.wasm /usr/share/nginx/html/license.wasm
COPY --from=wasmbuild /src/telemetry.bin /usr/share/nginx/html/telemetry.bin
COPY src/ /usr/share/nginx/html/src/