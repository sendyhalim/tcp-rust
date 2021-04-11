fn main() -> anyhow::Result<()> {
  let network_interface = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
  let mut buf = [0u8; 1504];

  loop {
    let nbytes = network_interface.recv(&mut buf[..])?;
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
