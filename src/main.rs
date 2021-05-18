use std::collections::hash_map::Entry;
use tcp_rust::Quad;

fn main() -> anyhow::Result<()> {
  loop {
    let nbytes = network_interface.recv(&mut buf[..])?;
    let packet_info_len = 0;
    // let packet_info_len = 4;

    // Data link protocol
    // let ethernet_frame_flags = u16::from_be_bytes([buf[0], buf[1]]);
    // let ethernet_frame_proto = u16::from_be_bytes([buf[2], buf[3]]);

    // if ethernet_frame_proto != 0x0800 {
    // // no ipv4
    // continue;
    // }

    // IP Level protocol
    match etherparse::Ipv4HeaderSlice::from_slice(&buf[packet_info_len..nbytes]) {
      Ok(ipv4_header) => {
        let iph_src = ipv4_header.source_addr();
        let iph_dst = ipv4_header.destination_addr();
        let iph_proto = ipv4_header.protocol();

        // Not TCP https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        if iph_proto != 0x06 {
          continue;
        }

        let tcp_header_start_index = packet_info_len + ipv4_header.slice().len() as usize;

        match etherparse::TcpHeaderSlice::from_slice(&buf[tcp_header_start_index..nbytes]) {
          Ok(tcp_header) => {
            let src_port = tcp_header.source_port();
            let dst_port = tcp_header.destination_port();
            let data_start_index = tcp_header_start_index + tcp_header.slice().len();

            let quad_entry = connection_by_quad.entry(Quad {
              src: (iph_src, src_port),
              dst: (iph_dst, dst_port),
            });

            match quad_entry {
              Entry::Occupied(mut map_entry) => {
                map_entry.get_mut().on_packet(
                  &network_interface,
                  ipv4_header,
                  tcp_header,
                  &buf[data_start_index..nbytes],
                )?;
              }
              Entry::Vacant(map_entry) => {
                if let Some(connection) = tcp_rust::TcpConnection::accept(
                  &network_interface,
                  ipv4_header,
                  tcp_header,
                  &buf[data_start_index..nbytes],
                )? {
                  map_entry.insert(connection);
                }
              }
            }
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
          &buf[packet_info_len..nbytes]
        );
      }
    }
  }
}
