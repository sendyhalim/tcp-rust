use std::io::Result;
use std::net::Ipv4Addr;

pub enum TcpState {
  Closed,
  Listen,
  SynRcvd,
  Established, // ETAB
}
// TCP Header
// 32 bit per lines ~> 4 bytes per line
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// Receive Sequence Space
///
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
pub struct RecvSequenceSpace {
  ///  receive next
  nxt: u32,

  /// receive window
  wnd: u16,

  /// receive urgent pointer
  up: bool,

  /// initial receive sequence number
  irs: u32,
}

/// The following diagrams may help to relate some of these variables to
/// the sequence space.
///
/// Send Sequence Space
///
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
pub struct SendSequenceSpace {
  /// send unacknowledged
  una: u32,

  /// send next
  nxt: u32,

  /// send window
  wnd: u16,

  /// send urgent pointer
  up: bool,

  /// segment sequence number used for last window update
  wl1: usize,

  /// segment acknowledgment number used for last window update
  wl2: usize,

  /// initial send sequence number
  iss: u32,
}

pub struct TcpConnection {
  state: TcpState,
  recv: RecvSequenceSpace,
  send: SendSequenceSpace,
}

impl TcpConnection {
  pub fn accept<'a>(
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> Result<Option<Self>> {
    let mut buf = [0u8; 1500];

    // Not synchronized
    if !tcph.syn() {
      return Ok(None);
    }

    let iss = 0;
    let mut connection = TcpConnection {
      state: TcpState::SynRcvd,
      send: SendSequenceSpace {
        // Decide on stuff we're sending them
        iss,
        una: iss,
        nxt: iss + 1,
        wnd: 10,

        up: false,
        wl1: 0,
        wl2: 0,
      },
      recv: RecvSequenceSpace {
        // Keep track of sender info
        nxt: tcph.sequence_number() + 1,
        wnd: tcph.window_size(),
        irs: tcph.sequence_number(),
        up: false,
      },
    };

    // First create a tcp header
    let mut syn_ack = etherparse::TcpHeader::new(
      tcph.destination_port(),
      tcph.source_port(),
      connection.send.iss, // Sequence number
      connection.send.wnd, // Window size
    );

    syn_ack.acknowledgment_number = connection.recv.nxt;
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

    nic.send(&buf[..written_count])?;

    return Ok(Some(connection));

    // eprintln!(
    // "{}:{} -> {}:{} {}b of  tcp",
    // iph.source_addr(),
    // tcph.source_port(),
    // iph.destination_addr(),
    // tcph.destination_port(),
    // data.len()
    // )
  }

  pub fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> Result<usize> {
    eprintln!("Foo {:02x?}", data);
    return Ok(0);
  }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
  pub src: (Ipv4Addr, u16), // (ip address, port)
  pub dst: (Ipv4Addr, u16),
}
