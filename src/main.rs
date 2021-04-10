use std::io::Read;

fn main() -> anyhow::Result<()> {
  let tun_config = tun::Configuration::default();
  let mut network_interface: tun::platform::Device = tun::create(&tun_config)?;

  #[cfg(target_os = "linux")]
  config.platform(|config| {
    config.packet_information(true);
  });

  let mut buf = [0u8; 1504];

  loop {
    let nbytes = network_interface.read(&mut buf[..])?;
    let flags = u16::from_be_bytes([buf[0], buf[1]]);
    let proto = u16::from_be_bytes([buf[2], buf[3]]);

    if proto != 0x0800 {
      // no ipv4
      continue;
    }

    eprintln!(
      "read {} bytes (flags: {:x}, proto: {:x}): {:x?}",
      nbytes - 4,
      flags,
      proto,
      &buf[4..nbytes]
    );
  }
}
