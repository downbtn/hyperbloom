FROM alpine:3.22.0

LABEL version="0.1"
LABEL description="Container to build the target decoder image for Hyperbloom"

WORKDIR /root

RUN apk add \
    python3=3.12.11-r0 \
    gcc-arm-none-eabi=15.1.0-r0 \
    binutils-arm-none-eabi=2.44-r0 \
    newlib-arm-none-eabi=4.5.0.20241231-r0 \
    make=4.4.1-r3 \
    libtool=2.5.4-r1

# TODO: remove newlib after completely removing libc

ENV MAXIM_PATH=/decoder/lib/msdk-2024_10

WORKDIR /decoder

ENTRYPOINT ["sh", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
