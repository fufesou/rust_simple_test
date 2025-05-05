use rdev::{simulate, EventType, Key, SimulateError};
use std::{thread, time};

fn send(event_type: &EventType) {
    let delay = time::Duration::from_millis(20);
    match simulate(event_type) {
        Ok(()) => (),
        Err(SimulateError) => {
            println!("We could not send {:?}", event_type);
        }
    }
    // Let ths OS catchup (at least MacOS)
    thread::sleep(delay);
}

fn main() {
    let k_shift = Key::RawKey(rdev::RawKey::WinVirtualKeycode(50));
    let k_r_bracket = Key::RawKey(rdev::RawKey::WinVirtualKeycode(34));
    send(&EventType::KeyPress(k_shift.clone()));
    send(&EventType::KeyPress(k_r_bracket.clone()));
    send(&EventType::KeyRelease(k_r_bracket));
    send(&EventType::KeyRelease(k_shift));
}
