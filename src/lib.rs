use std::io::Result;
use std::io::Write;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
  pub src: (Ipv4Addr, u16), // (ip address, port)
  pub dst: (Ipv4Addr, u16),
}

pub enum TcpState {
  FinWait1,
  FinWait2,
  SynRcvd,
  Established, // ETAB
  Closing,
}

impl TcpState {
  pub fn is_synchronized(&self) -> bool {
    return match *self {
      TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => true,
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
  recv: RecvSequenceSpace,
  send: SendSequenceSpace,
  tcph: etherparse::TcpHeader,
  iph: etherparse::Ipv4Header,
}

impl TcpConnection {
  pub fn accept<'a>(
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> Result<Option<Self>> {
    let buf = [0u8; 1500];

    if !tcph.syn() {
      // No SYN, not valid because we want SYN at first connection initiation step
      Ok(None);
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
      tcph: etherparse::TcpHeader::new(
        tcph.destination_port(),
        tcph.source_port(),
        connection.send.iss, // Sequence number
        connection.send.wnd, // Window size
      ),
    };

    self.tcph.syn = true;
    self.tcph.ack = true;

    connection.write(nic, &[])?;

    return Ok(Some(connection));
  }

  pub fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> Result<usize> {
    let ack_number = tcph.acknowledgment_number();

    if !is_between_wrapped(self.send.una, ack_number, self.send.nxt.wrapping_add(1)) {
      if !self.state.is_synchronized() {
        // According to reset generation (rfc) we should send reset
        self.send_rst(nic);
      }

      return Ok(());


    self.snd.una = ack_number;

    let seq_number = tcph.sequence_number();
    let recv_nxt = connection.recv.nxt;
    let nxt_and_wnd = recv_nxt + connection.recv.wnd;
    let win_size = tcph.window_size();
    let slen = data.len();

    if tcph.fin() {
      slen = slen + 1;
    }

    if tcph.syn() {
      slen = slen + 1;
    }

    if slen == 0 {
      if win_size == 0 && seq_number != recv_nxt {
        return Ok(());
      }

      if win_size > 0 && !is_between_wrapped(recv_nxt.wrapping_sub(1), seq_number, nxt_and_wnd) {
        return Ok(());
      }
    } else if slen > 0 {
      if win_size == 0 {
        return Ok(());
      }

      if win_size > 0
        && !is_between_wrapped(recv_nxt.wrapping_sub(1), seq_number, nxt_and_wnd)
        && !is_between_wrapped(
          recv_nxt.wrapping_sub(1),
          seq_number.wrapping_add(slen - 1),
          nxt_and_wnd,
        )
      {
        return Ok(());
      }
    }

    self.recv.nxt = seq_number.wrapping_add(slen);

    match *self.state {
      TcpState::SynRcvd => {
        if !tcph.ack() {
          return Ok(());
        }

        // Must have acked our SYN, since we detected at least one acked byte, and we
        // have only sent one byte (SYN)
        self.state = State::Established;

        // Just for testing
        self.tcph.fin = true;
        self.write(nic, &[]);
        self.state = TcpState::FinWait1;
      }
      TcpState::Established => {
        unimplemented!();
      }
      TcpState::FinWait1 => {
        // We receive fin from the otherside.
        // Not sure about this yet, why we're checking this
        if !tcph.fin() || !data.is_empty() {
          unimplemented!();
        }

        // Must have acked our FIN, since we detected at least one acked byte, and we
        // have only sent one byte (FIN)
        self.tcph.fin = false;
        self.write(nic, &[]);
        self.state = TcpState::Closing;
      }
      TcpState::Closing => {
        // At this state, we need to wait for our FIN to be acked by the otherside
        // Not sure about this yet, why we're checking this
        if !tcph.fin() || !data.is_empty() {
          unimplemented!();
        }

        // Must have acked our FIN, since we detected at least one acked byte, and we
        // have only sent one byte (FIN)
        self.tcph.fin = false;
        self.write(nic, &[]);
        self.state = TcpState::Closing;
      }
    }

    return Ok(());
  }

  fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
    // TODO: Need to fix sequence number of our tcph according to RFC
    self.tcph.rst = true;
    self.tcph.sequence_number = 0;
    self.tcph.acknowledgment_number = 0;
    self.write(nic, &[]);

    return Ok(());
  }

  fn write<'a>(&mut self, nic: &tun_tap::Iface, payload: &'a [u8]) -> io::Result<usize> {
    let mut buf = [0u8; 1500];
    self.tcph.sequence_number = self.send.nxt;
    self.tcph.acknowledgment_number = self.recv.nxt;

    let ip_payload_size = std::cmp::min(
      buf.len(),
      self.tcph.header_len() + self.iph.header_len() + payload.len(),
    );
    self.iph.set_payload_len(ip_payload_size);

    let mut unwritten_buf = &mut buf[..];

    // Write iph and tcph into unwritten_buf
    self.iph.write(&mut unwritten_buf);
    self.tcph.write(&mut unwritten_buf);

    // Write into unwritten_buf, the "write" method is kind of different between headers and buf, go
    // to function definition for more details
    let written_payload_size = unwritten_buf.write(payload)?;
    let unwritten_count = unwritten_buf.len()?;

    self.send.nxt = self.send.nxt.wrapping_add(written_payload_size as usize);

    if self.tcph.syn {
      self.send.nxt = self.send.nxt.wrapping_add(1);
      self.tcp.syn = false;
    }

    if self.tcph.fin {
      self.send.nxt = self.send.nxt.wrapping_add(1);
      self.tcp.syn = false;
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

  // use std::cmp::Ordering;

  // match start.cmp(x) {
  //   Ordering::Equal => return false,
  //   Ordering::Less => {
  //     if end >= start && end < x {
  //       return false;
  //     }
  //   }
  //   Ordering::Greater => {
  //     if end < start && end < x {
  //     } else {
  //       return false;
  //     }
  //   }
  // }

  // return true;
}
