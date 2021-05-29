use bitflags::bitflags;
use std::collections::VecDeque;
use std::io;
use std::io::Write;

bitflags! {
    pub(crate) struct PacketReadyAction: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
pub enum TcpState {
  SynRcvd,
  Established, // ETAB
  FinWait1,
  FinWait2,
  TimeWait,
}

impl TcpState {
  pub fn is_synchronized(&self) -> bool {
    return match *self {
      TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait => true,
      _ => false,
    };
  }
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
  send: SendSequenceSpace,
  recv: RecvSequenceSpace,
  iph: etherparse::Ipv4Header,
  tcph: etherparse::TcpHeader,

  // Bytes that we've recieved from the other side of TCP
  // but our caller (lib) haven't read yet
  pub(crate) incoming: VecDeque<u8>,

  // Bytes that we've sent to the other side of TCP
  // but they haven't ack-ed yet. We have these for
  // TCP retransmission purposes.
  pub(crate) outgoing: VecDeque<u8>,
}

impl TcpConnection {
  pub(crate) fn is_recv_closed(&self) -> bool {
    if let TcpState::TimeWait = self.state {
      return true;
    }

    return false;
  }

  pub(crate) fn packet_ready_action(&self) -> PacketReadyAction {
    let mut ready_action = PacketReadyAction::empty();

    if self.is_recv_closed() || !self.incoming.is_empty() {
      ready_action |= PacketReadyAction::READ;
    }

    return ready_action;
  }

  pub fn accept<'a>(
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> io::Result<Option<Self>> {
    let buf = [0u8; 1500];

    if !tcph.syn() {
      // No SYN, not valid because we want SYN at first connection initiation step
      return Ok(None);
    }

    let iss = 0;
    let wnd = 1024;

    let mut connection = TcpConnection {
      incoming: Default::default(),
      outgoing: Default::default(),
      state: TcpState::SynRcvd,
      send: SendSequenceSpace {
        // Decide on stuff we're sending them
        iss,
        una: iss,
        nxt: iss,
        wnd,

        up: false,
        wl1: 0,
        wl2: 0,
      },
      recv: RecvSequenceSpace {
        // Keep track of sender info
        irs: tcph.sequence_number(),
        nxt: tcph.sequence_number() + 1,
        wnd: tcph.window_size(),
        up: false,
      },
      tcph: etherparse::TcpHeader::new(
        tcph.destination_port(),
        tcph.source_port(),
        iss, // Sequence number
        wnd, // Window size
      ),
      // Then we'll need to send back wrapped as ipv4 package
      iph: etherparse::Ipv4Header::new(
        0,
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
      ),
    };

    connection.tcph.syn = true;
    connection.tcph.ack = true;

    connection.write(nic, &[])?;

    return Ok(Some(connection));
  }

  pub(crate) fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> io::Result<PacketReadyAction> {
    eprintln!("ON PACKET, current state: {:?}", self.state);
    let seq_number = tcph.sequence_number();
    let mut slen = data.len() as u32;

    if tcph.fin() {
      slen = slen + 1;
    }

    if tcph.syn() {
      slen = slen + 1;
    }

    let ack_number = tcph.acknowledgment_number();
    let recv_nxt = self.recv.nxt;
    let nxt_and_wnd = recv_nxt.wrapping_add(self.recv.wnd as u32);
    let win_size = tcph.window_size();

    // let okay = if slen == 0 {
    // // zero-length segment has separate rules for acceptance
    // if self.recv.wnd == 0 {
    // if seq_number != self.recv.nxt {
    // false
    // } else {
    // true
    // }
    // } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, nxt_and_wnd) {
    // false
    // } else {
    // true
    // }
    // } else {
    // if self.recv.wnd == 0 {
    // false
    // } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, nxt_and_wnd)
    // && !is_between_wrapped(
    // self.recv.nxt.wrapping_sub(1),
    // seq_number.wrapping_add(slen - 1),
    // nxt_and_wnd,
    // )
    // {
    // false
    // } else {
    // true
    // }
    // };

    let okay = if slen == 0 {
      if win_size == 0 && seq_number != recv_nxt {
        false
      } else if win_size > 0
        && !is_between_wrapped(recv_nxt.wrapping_sub(1), seq_number, nxt_and_wnd)
      {
        false
      } else {
        true
      }
    } else if slen > 0 {
      if win_size == 0 {
        false
      } else if win_size > 0
        && !(is_between_wrapped(recv_nxt.wrapping_sub(1), seq_number, nxt_and_wnd)
          || is_between_wrapped(
            recv_nxt.wrapping_sub(1),
            seq_number.wrapping_add(slen as u32 - 1),
            nxt_and_wnd,
          ))
      {
        false
      } else {
        true
      }
    } else {
      true
    };

    if !okay {
      eprintln!("Not ok will return");
      self.write(nic, &[])?;
      return Ok(self.packet_ready_action());
    }

    self.recv.nxt = seq_number.wrapping_add(slen);

    if !tcph.ack() {
      eprintln!("NO ACK flag set, will return");
      return Ok(self.packet_ready_action());
    }

    if let TcpState::SynRcvd = self.state {
      eprintln!("SYNC RCVD, will set to ESTABLISHED");

      if is_between_wrapped(
        self.send.una.wrapping_sub(1),
        ack_number,
        self.send.nxt.wrapping_add(1),
      ) {
        self.state = TcpState::Established;
      } else {
        // TODO: RST
      }
    }

    if let TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 = self.state {
      if is_between_wrapped(self.send.una, ack_number, self.send.nxt.wrapping_add(1)) {
        self.send.una = ack_number;
      }

      // TODO: will take a look again later, read data

      assert!(data.is_empty());

      // Just for testing, we'll terminate the connection (going into FIN state)
      eprintln!("CONNECTION is ESTABLISHED, will send FIN");
      if let TcpState::Established = self.state {
        self.tcph.fin = true;
        self.write(nic, &[])?;
        self.state = TcpState::FinWait1;
      }
    }

    if let TcpState::FinWait1 = self.state {
      if self.send.una == self.send.iss + 2 {
        // our FIN has ben ACKed, plus 2 because we also need to include 1 byte of SYN.
        // SYN + FIN = 2 bytes
        eprintln!("THEY'VE ACKED OUR FIN");
        self.state = TcpState::FinWait2;
      }
    }

    if tcph.fin() {
      match self.state {
        TcpState::FinWait2 => {
          // We're done with the connection
          eprintln!("THEY'VE FINED");
          self.write(nic, &[]);
          self.state = TcpState::TimeWait;
        }
        _ => unreachable!(),
      }
    }

    return Ok(self.packet_ready_action());
  }

  fn send_rst(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
    // TODO: Need to fix sequence number of our tcph according to RFC
    self.tcph.rst = true;
    self.tcph.sequence_number = 0;
    self.tcph.acknowledgment_number = 0;
    self.write(nic, &[]);

    return Ok(());
  }

  fn write(&mut self, nic: &tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
    let mut buf = [0u8; 1500];
    self.tcph.sequence_number = self.send.nxt;
    self.tcph.acknowledgment_number = self.recv.nxt;

    dbg!(self.tcph.sequence_number);
    dbg!(self.tcph.acknowledgment_number);
    let ip_payload_size = std::cmp::min(
      buf.len(),
      self.tcph.header_len() as usize + self.iph.header_len() as usize + payload.len(),
    );

    self
      .iph
      .set_payload_len(ip_payload_size - self.iph.header_len() as usize);

    // finally we can calculate the tcp checksum and write out the tcp header
    self.tcph.checksum = self
      .tcph
      .calc_checksum_ipv4(&self.iph, &[])
      .expect("failed to compute checksum");

    let mut unwritten_buf = &mut buf[..];

    // Write iph and tcph into unwritten_buf
    self.iph.write(&mut unwritten_buf);
    self.tcph.write(&mut unwritten_buf);

    // Write into unwritten_buf, the "write" method is kind of different between headers and buf, go
    // to function definition for more details
    let written_payload_size = unwritten_buf.write(payload)?;
    let unwritten_count = unwritten_buf.len();

    self.send.nxt = self.send.nxt.wrapping_add(written_payload_size as u32);

    if self.tcph.syn {
      self.send.nxt = self.send.nxt.wrapping_add(1);
      self.tcph.syn = false;
    }

    if self.tcph.fin {
      self.send.nxt = self.send.nxt.wrapping_add(1);
      self.tcph.fin = false;
    }

    nic.send(&buf[..buf.len() - unwritten_count])?;

    return Ok(written_payload_size);
  }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
  // | -- S --- X --- E -- |
  if start < x {
    return x < end ||
    // or this case is true
    // | -- E --- S --- X |
        end < start;
  }
  // | -- X --- E --- S -- |
  else if start > x {
    return x < end && end < start;
  }

  return false;
}
