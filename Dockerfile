FROM rustlang/rust:nightly-alpine3.15 as cargo-build

# check version
RUN cargo --version

# fetch crates.io index
# RUN cargo install lazy_static
RUN cargo search --limit 0

RUN apk add --no-cache musl-dev
RUN apk --update add openssl openssl-dev

# RUN apk --update add gcc libc-dev
RUN apk --update add g++
RUN apk --update add protobuf-dev

# protobuf-compiler
# ->[alpine]>
# protobuf-c-compiler

# both make and cmake required: https://github.com/awslabs/aws-crt-python/issues/272#issuecomment-829590450
RUN apk add --no-cache make cmake

COPY ./ssi ./ssi
COPY ./oidc4vci-rs ./oidc4vci-rs

RUN ls -lah
WORKDIR ./oidc4vci-rs

RUN ls -lah

# RUN cargo +nightly build --release
RUN cargo +nightly build

CMD ["echo 'hi: seems to have built!'"]

# Run the binary
CMD ["./target/release/oidc4vci-rs"]
