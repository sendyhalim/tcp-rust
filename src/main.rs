use std::collections::HashMap;
use tcp_rust::Quad;
use tcp_rust::TcpState;

fn main() -> anyhow::Result<()> {
  let network_interface = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
  let mut buf = [0u8; 1604];
  let mut connection_by_quad: HashMap<Quad, TcpState> = Default::default();

  loop {
    let nbytes = network_interface.recv(&mut buf[..])?;

    // Data link protocol
    let ethernet_frame_flags = u16::from_be_bytes([buf[0], buf[1]]);
    let ethernet_frame_proto = u16::from_be_bytes([buf[2], buf[3]]);

    if ethernet_frame_proto != 0x0800 {
      // no ipv4
      continue;
    }

    // IP Level protocol
    match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
      Ok(ipv4_header) => {
        let iph_src = ipv4_header.source_addr();
        let iph_dst = ipv4_header.destination_addr();
        let iph_proto = ipv4_header.protocol();

        // Not TCP https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        if iph_proto != 0x06 {
          continue;
        }

        let tcp_header_start_index = 4 + ipv4_header.slice().len() as usize;

        match etherparse::TcpHeaderSlice::from_slice(&buf[tcp_header_start_index..nbytes]) {
          Ok(tcp_header) => {
            let src_port = tcp_header.source_port();
            let dst_port = tcp_header.destination_port();
            let data_start_index = tcp_header_start_index + tcp_header.slice().len();

            connection_by_quad
              .entry(Quad {
                src: (iph_src, src_port),
                dst: (iph_dst, dst_port),
              })
              .or_default()
              .on_packet(
                &network_interface,
                ipv4_header,
                tcp_header,
                &buf[data_start_index..],
              )?;
          }
          Err(err) => {
            eprintln!("Ignoring weird TCP packet {:?}", err);
          }
        }

        // eprintln!(
        // "read {} bytes (flags: {:x}, proto: {:x}): {:x?}",
        // nbytes - 4,
        // ethernet_frame_flags,
        // ethernet_frame_proto,
        // &buf[4..nbytes]
        // );
      }
      Err(err) => {
        eprintln!(
          "Ignoring weird ipv4 packet {:?} {:x?}",
          err,
          &buf[4..nbytes]
        );
      }
    }
  }
}
