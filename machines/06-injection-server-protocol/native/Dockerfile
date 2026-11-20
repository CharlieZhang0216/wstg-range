FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
COPY native.c .
RUN gcc -O0 -fno-stack-protector -z execstack -no-pie -static -o native native.c

FROM alpine:3.20
COPY --from=build /native /native
EXPOSE 9000
CMD ["/native"]