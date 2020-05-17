FROM ekidd/rust-musl-builder:1.43.0

ADD --chown=rust:rust . ./

CMD cargo build --release