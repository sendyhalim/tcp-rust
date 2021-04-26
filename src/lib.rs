use std::io::Result;
use std::net::Ipv4Addr;

pub enum TcpState {
  Closed,
  Listen,
  Established, // ETAB
}

impl Default for TcpState {
  fn default() -> Self {
    return TcpState::Listen;
  }
}

impl TcpState {
  pub fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> Result<usize> {
    match self {
      TcpState::Closed => {
        return Ok(0);
      }
      TcpState::Listen => {
        let mut buf = [0u8; 1500];

        // Not synchronized
        if !tcph.syn() {
          return Ok(0);
        }

        // Let's establish a conneciton if there's a sync req

        // First create a tcp header
        let mut syn_ack = etherparse::TcpHeader::new(
          tcph.destination_port(),
          tcph.source_port(),
          unimplemented!(), // Sequence number
          unimplemented!(), // Window size
        );

        syn_ack.syn = true;
        syn_ack.ack = true;

        // Then we'll need to send back wrapped as ipv4 package
        let mut ipv4header = etherparse::Ipv4Header::new(
          syn_ack.header_len(),
          64, // In seconds based on spec
          etherparse::IpTrafficClass::Tcp,
          [
            iph.destination()[0],
            iph.destination()[1],
            iph.destination()[2],
            iph.destination()[3],
          ],
          [
            iph.source()[0],
            iph.source()[1],
            iph.source()[2],
            iph.source()[3],
          ],
        );

        let written_count = {
          let mut unwritten_buf = &mut buf[..];
          ipv4header.write(&mut unwritten_buf);
          syn_ack.write(&mut unwritten_buf);
          unwritten_buf.len()
        };

        return nic.send(&buf[..written_count]);
      }
      TcpState::Established => {
        return Ok(0);
      }
    }
    // eprintln!(
    // "{}:{} -> {}:{} {}b of  tcp",
    // iph.source_addr(),
    // tcph.source_port(),
    // iph.destination_addr(),
    // tcph.destination_port(),
    // data.len()
    // )
  }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
  pub src: (Ipv4Addr, u16), // (ip address, port)
  pub dst: (Ipv4Addr, u16),
}
