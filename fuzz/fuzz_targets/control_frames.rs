#![no_main]

use bloom_relay_protocol::{ControlDecoder, MAX_CONTROL_BODY};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CONTROL_BODY || data.is_empty() {
        return;
    }
    let mut whole = ControlDecoder::default();
    let expected = whole.push(data);
    let mut fragmented = ControlDecoder::default();
    let chunk_size = usize::from(data[0] % 64).max(1);
    let mut observed = Vec::new();
    let mut error = None;
    for chunk in data.chunks(chunk_size) {
        match fragmented.push(chunk) {
            Ok(events) => observed.extend(events),
            Err(reason) => {
                error = Some(reason);
                break;
            }
        }
    }
    match expected {
        Ok(events) => {
            assert!(error.is_none());
            assert_eq!(observed, events);
        }
        Err(_) => assert!(error.is_some()),
    }
});
