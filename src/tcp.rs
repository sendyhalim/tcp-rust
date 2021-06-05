// LATEST STREAM: Want to skip vecdeque of outgoing by nunacked (ontick)
use bitflags::bitflags;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::time;
use std::time::Duration;

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

  timers: Timers,

  // Bytes that we've recieved from the other side of TCP
  // but our caller (lib) haven't read yet
  pub(crate) incoming: VecDeque<u8>,

  // Bytes that we've sent to the other side of TCP
  // but they haven't ack-ed yet. We have these for
  // TCP retransmission purposes.
  pub(crate) outgoing: VecDeque<u8>,

  pub(crate) closed: bool,
  closed_at: Option<u32>,
}

struct Timers {
  send_times: BTreeMap<u32, time::Instant>,
  srtt: f64,
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
      closed_at: None,
      closed: false,
      timers: Timers {
        send_times: Default::default(),
        srtt: time::Duration::from_secs(60).as_secs_f64(),
      },
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

    connection.write(nic, connection.send.nxt, 0)?;

    return Ok(Some(connection));
  }

  pub(crate) fn on_tick<'a>(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
    if let TcpState::FinWait2 | TcpState::TimeWait = self.state {
      // we have shutdown our write side and the other side acked, no need to (re)transmit anything
      return Ok(());
    }

    let unacked_count = self
      .closed_at
      .unwrap_or(self.send.nxt)
      .wrapping_sub(self.send.una);
    let unsent = self.outgoing.len() as u32 - unacked_count;

    let waited_for = self
      .timers
      .send_times
      .range(self.send.una..)
      .next()
      .map(|t| t.1.elapsed());

    let should_retransmit = if let Some(waited_for) = waited_for {
      waited_for > time::Duration::from_secs(1)
        && waited_for.as_secs_f64() > (1.5 * self.timers.srtt)
    } else {
      false
    };

    if should_retransmit {
      // Should retransmit things
      // Formula from RFC
      // let allowed_data_to_be_sent_count = self.send.una + self.send.wnd - 1;
      let resend_size = std::cmp::min(self.outgoing.len() as u32, self.send.wnd as u32);

      // If we have space in the window and the connection should be closing
      // then we'll retransmit the fin.
      if resend_size < self.send.wnd as u32 && self.closed {
        self.tcph.fin = true;
        self.closed_at = Some(self.send.una.wrapping_add(self.outgoing.len() as u32));
      }

      self.write(nic, self.send.una, resend_size as usize)?;
    } else {
      // Send new data if there's space in the window
      if unsent == 0 && self.closed_at.is_some() {
        // Nothing to do, all is sent!
        return Ok(());
      }

      let allowed = self.send.wnd as u32 - unacked_count;

      if allowed <= 0 {
        return Ok(());
      }

      let send_count = std::cmp::min(unsent, allowed);

      // Check whether we should sens find and have space to do so or not.
      if send_count < allowed && self.closed && self.closed_at.is_none() {
        self.tcph.fin = true;
        self.closed_at = Some(self.send.una.wrapping_add(self.outgoing.len() as u32));
      }

      // we want self.unacked[unacked_count..];
      //

      self.write(nic, self.send.nxt, send_count as usize)?;
    }

    return Ok(());
  }

  pub(crate) fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> io::Result<PacketReadyAction> {
    let seq_number = tcph.sequence_number();
    let mut slen = data.len() as u32;

    if tcph.fin() {
      slen = slen + 1;
    }

    if tcph.syn() {
      slen = slen + 1;
    }

    let recv_nxt = self.recv.nxt;
    let nxt_and_wnd = recv_nxt.wrapping_add(self.recv.wnd as u32);
    let win_size = tcph.window_size();

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
      self.write(nic, self.send.nxt, 0)?;
      return Ok(self.packet_ready_action());
    }

    if !tcph.ack() {
      // Got SYNc for initial handshake
      if tcph.syn() {
        assert!(data.is_empty());
        self.recv.nxt = seq_number.wrapping_add(1);
      }

      eprintln!("NO ACK flag set, will return");
      return Ok(self.packet_ready_action());
    }

    let ack_number = tcph.acknowledgment_number();

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
        if !self.outgoing.is_empty() {
          let nacked = self
            .outgoing
            .drain(..ack_number.wrapping_sub(self.send.una) as usize)
            .count();

          let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

          let una = self.send.una;
          let mut srtt = &mut self.timers.srtt;

          self
            .timers
            .send_times
            .extend(old.into_iter().filter_map(|(seq, sent)| {
              if is_between_wrapped(una, seq_number, ack_number) {
                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                None
              } else {
                Some((seq, sent))
              }
            }));
        }

        self.send.una = ack_number;
      }
    }

    if let TcpState::FinWait1 = self.state {
      eprintln!(
        "ON_PACKET state {:?}, closed_at {:?} una {}",
        self.state, self.closed_at, self.send.una
      );

      if let Some(closed_at) = self.closed_at {
        if self.send.una == closed_at.wrapping_add(1) {
          // our FIN has been ACKed!
          self.state = TcpState::FinWait2;
        }
      }
    }

    if !data.is_empty() {
      if let TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 = self.state {
        // TODO: will take a look again later, read data

        // Readers will be awoken automatically
        // because we've checked the self.incoming size at self.ready_action();
        let mut data_offset = (self.recv.nxt - seq_number) as usize;

        // Guard
        // We must have received a re-transmitted FIN that we've already seen
        // nxt points to beyond the fin but the fin is not in the data.
        if data_offset > data.len() {
          assert_eq!(data_offset, data.len() + 1);
          data_offset = 0;
        }

        self.incoming.extend(&data[data_offset..]);

        self.recv.nxt = seq_number
          .wrapping_add(data.len() as u32)
          .wrapping_add(if tcph.fin() { 1 } else { 0 });

        // Send acknowledgement
        self.write(nic, self.send.nxt, 0)?;
      }
    }

    if tcph.fin() {
      eprintln!(
        "STATEE {:?} closed {}, closed_at {:?}",
        self.state, self.closed, self.closed_at
      );

      match self.state {
        TcpState::FinWait2 => {
          // We're done with the connection
          eprintln!("THEY'VE FINED");
          self.recv.nxt = self.recv.nxt.wrapping_add(1); // Expect 1 byte for FIN
          self.write(nic, self.send.nxt, 0)?;
          self.state = TcpState::TimeWait;
        }
        _ => unimplemented!(),
      }
    }

    return Ok(self.packet_ready_action());
  }

  fn send_rst(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
    // TODO: Need to fix sequence number of our tcph according to RFC
    self.tcph.rst = true;
    self.tcph.sequence_number = 0;
    self.tcph.acknowledgment_number = 0;
    self.write(nic, self.send.nxt, 0);

    return Ok(());
  }

  fn write(
    &mut self,
    nic: &tun_tap::Iface,
    seq_of_first_byte: u32,
    mut limit: usize,
  ) -> io::Result<usize> {
    let mut buf = [0u8; 1500];

    self.tcph.sequence_number = seq_of_first_byte;
    self.tcph.acknowledgment_number = self.recv.nxt;

    println!(
      "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
      self.recv.nxt - self.recv.irs,
      seq_of_first_byte,
      limit,
      self.tcph.syn,
      self.tcph.fin,
    );

    let mut offset = seq_of_first_byte.wrapping_sub(self.send.una) as usize;

    if let Some(closed_at) = self.closed_at {
      if seq_of_first_byte == closed_at.wrapping_add(1) {
        // trying to write following FIN
        offset = 0;
        limit = 0;
      }
    }

    let (mut head, mut tail) = self.outgoing.as_slices();

    if head.len() >= offset {
      head = &head[offset..];
    } else {
      let skipped_count = head.len();
      head = &[];
      tail = &tail[offset - skipped_count..];
    }

    let max_data = std::cmp::min(limit, head.len() + tail.len());

    let ip_payload_size = std::cmp::min(
      buf.len(),
      self.tcph.header_len() as usize + self.iph.header_len() as usize + max_data,
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
    let written_payload_size = {
      let mut written = 0;
      let mut limit = max_data;

      let p1l = std::cmp::min(limit, head.len());
      written += unwritten_buf.write(&head[..p1l])?;
      limit -= written;

      let p2l = std::cmp::min(limit, tail.len());
      written += unwritten_buf.write(&tail[..p2l])?;
      written
    };

    let unwritten_count = unwritten_buf.len();

    let mut next_seq = seq_of_first_byte.wrapping_add(written_payload_size as u32);

    self.send.nxt = self.send.nxt.wrapping_add(written_payload_size as u32);

    if self.tcph.syn {
      next_seq = next_seq.wrapping_add(1);
      self.tcph.syn = false;
    }

    if self.tcph.fin {
      next_seq = next_seq.wrapping_add(1);
      self.tcph.fin = false;
    }

    if wrapping_lt(self.send.nxt, next_seq) {
      self.send.nxt = next_seq;
    }

    nic.send(&buf[..buf.len() - unwritten_count])?;

    self
      .timers
      .send_times
      .insert(seq_of_first_byte, time::Instant::now());

    return Ok(written_payload_size);
  }

  pub(crate) fn close(&mut self) -> io::Result<()> {
    self.closed = true;

    match self.state {
      TcpState::SynRcvd | TcpState::Established => {
        self.state = TcpState::FinWait1;
      }
      TcpState::FinWait1 | TcpState::FinWait2 => {}
      _ => {
        return Err(io::Error::new(
          io::ErrorKind::NotConnected,
          "already closing",
        ))
      }
    }

    return Ok(());
  }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
  // From RFC1323:
  //     TCP determines if a data segment is "old" or "new" by testing
  //     whether its sequence number is within 2**31 bytes of the left edge
  //     of the window, and if it is not, discarding the data as "old".  To
  //     insure that new data is never mistakenly considered old and vice-
  //     versa, the left edge of the sender's window has to be at most
  //     2**31 away from the right edge of the receiver's window.
  lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
  return wrapping_lt(start, x) && wrapping_lt(x, end);
  // // | -- S --- X --- E -- |
  // if start < x {
  //   return x < end ||
  //   // or this case is true
  //   // | -- E --- S --- X |
  //       end < start;
  // }
  // // | -- X --- E --- S -- |
  // else if start > x {
  //   return x < end && end < start;
  // }

  // return false;
}
