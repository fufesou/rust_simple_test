use std::io::Read;

use cpal::traits::{DeviceTrait, HostTrait};

fn main() {
    let host = cpal::default_host();
    let device = host.default_output_device().unwrap();
    println!(
        "Default output device: {}",
        device.name().unwrap_or("".to_owned())
    );
    println!("\nPress any key to exit...");
    let _ = std::io::stdin().read(&mut [0u8]).unwrap();
}
