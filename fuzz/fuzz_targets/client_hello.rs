#![no_main]

use bloom_relay_protocol::{MAX_CLIENT_HELLO, validate_hostname};
use libfuzzer_sys::fuzz_target;
use rustls::server::Acceptor;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CLIENT_HELLO || data.is_empty() {
        return;
    }
    // Match the gateway's incremental Acceptor path, including arbitrary TLS
    // record boundaries. The first byte selects the read chunk size.
    let chunk_size = usize::from(data[0]).max(1);
    let mut parser = Acceptor::default();
    for chunk in data.chunks(chunk_size) {
        if parser.read_tls(&mut Cursor::new(chunk)).is_err() {
            break;
        }
        match parser.accept() {
            Ok(Some(hello)) => {
                if let Some(host) = hello.client_hello().server_name() {
                    let _ = validate_hostname(host);
                }
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
});
