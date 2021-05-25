use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Default)]
struct FooBar {
  connection_manager: Mutex<ConnectionManager>,
  pending_var: Condvar,
}

type InterfaceHandle = Arc<FooBar>;

fn packet_loop(
  mut network_interface: tun_tap::Iface,
  interface_handle: InterfaceHandle,
) -> std::io::Result<()> {
  let mut buf = [0u8; 1504];

  loop {
    // Set timeout for this recv for TCP timers or ConnectionManager::terminate
    let nbytes = network_interface.recv(&mut buf[..])?;
    let packet_info_len = 0;

    // If self.terminate && Arc::get_strong_refs(interface_handle) == 1; then
    // tear down all connections and return (stop the loop).

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
            let mut connection_manager_lock = interface_handle.connection_manager.lock().unwrap();

            // So connection_manager is actually a mutex guard
            // we need to deref it again explicitly here
            // because if not then it will throw error due to
            // we're trying to borrow twice when accessing:
            // A) connection_manager.connection_by_quad.entry(quad)
            // B) connection_manager.pending_by_port.get_mut(...)
            //
            // It's a different field but the mutext guard is guarding the whole
            // connection manager. By dereferencing explicitly we're explicitly
            // saying that we want the internal connection manager inside
            // the mutex guard so point A & B is valid to the Rust's compiler.
            let connection_manager = &mut *connection_manager_lock;

            let quad = Quad {
              src: (iph_src, src_port),
              dst: (iph_dst, dst_port),
            };
            let quad_entry = connection_manager.connection_by_quad.entry(quad);

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
                if let Some(pending) = connection_manager
                  .pending_by_port
                  .get_mut(&tcp_header.destination_port())
                {
                  if let Some(connection) = TcpConnection::accept(
                    &network_interface,
                    ipv4_header,
                    tcp_header,
                    &buf[data_start_index..nbytes],
                  )? {
                    map_entry.insert(connection);
                    pending.push_back(quad);

                    // Drop the lock first so it can be used when the blocked
                    // statements are unblocked.
                    drop(connection_manager_lock);
                    interface_handle.pending_var.notify_all();
                  }
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

pub struct Interface {
  interface_handle: Option<InterfaceHandle>,
  join_handle: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
  fn drop(&mut self) {
    self
      .interface_handle
      .as_mut()
      .unwrap()
      .connection_manager
      .lock()
      .unwrap()
      .terminate = true;

    drop(self.interface_handle.take());

    self
      .join_handle
      .take()
      .expect("interface dropped more than once")
      .join()
      .unwrap()
      .unwrap();
  }
}

#[derive(Default)]
struct ConnectionManager {
  terminate: bool,
  connection_by_quad: HashMap<Quad, TcpConnection>,
  pending_by_port: HashMap<u16, VecDeque<Quad>>,
}

impl Interface {
  pub fn new() -> io::Result<Self> {
    let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

    let connection_manager: InterfaceHandle = Arc::default();

    let join_handle = {
      let connection_manager = connection_manager.clone();

      thread::spawn(move || packet_loop(nic, connection_manager))
    };

    return Ok(Interface {
      join_handle: Some(join_handle),
      interface_handle: Some(connection_manager),
    });
  }

  pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
    let mut connection_manager = self
      .interface_handle
      .as_mut()
      .unwrap()
      .connection_manager
      .lock()
      .unwrap();

    match connection_manager.pending_by_port.entry(port) {
      Entry::Vacant(v) => {
        v.insert(VecDeque::new());
      }
      Entry::Occupied(_) => {
        return Err(io::Error::new(
          io::ErrorKind::AddrInUse,
          "port already bound",
        ));
      }
    }

    drop(connection_manager);

    return Ok(TcpListener {
      port,
      interface_handle: self.interface_handle.as_mut().unwrap().clone(),
    });
  }
}

pub struct TcpListener {
  port: u16,
  interface_handle: InterfaceHandle,
}

impl Drop for TcpListener {
  fn drop(&mut self) {
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();

    let pending = connection_manager
      .pending_by_port
      .remove(&self.port)
      .expect("port closed while listener is still active");

    for quad in pending {
      unimplemented!();
    }
  }
}

impl TcpListener {
  pub fn accept(&mut self) -> io::Result<TcpStream> {
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();

    loop {
      if let Some(quad) = connection_manager
        .pending_by_port
        .get_mut(&self.port)
        .expect("port closed while listener is still active")
        .pop_front()
      {
        return Ok(TcpStream {
          quad,
          interface_handle: self.interface_handle.clone(),
        });
      }

      connection_manager = self
        .interface_handle
        .pending_var
        .wait(connection_manager)
        .unwrap();
    }
  }
}

pub struct TcpStream {
  quad: Quad,
  interface_handle: InterfaceHandle,
}

impl Drop for TcpStream {
  fn drop(&mut self) {
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();

    if let Some(connection) = connection_manager.connection_by_quad.remove(&self.quad) {}
  }
}

impl TcpStream {
  pub fn shutdown(&mut self, how: std::net::Shutdown) -> io::Result<()> {
    // Gonna send a FIN
    unimplemented!();
  }
}

impl Read for TcpStream {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();
    let connection = connection_manager
      .connection_by_quad
      .get_mut(&self.quad)
      .ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::ConnectionAborted,
          "stream was terminated unexpectedly",
        )
      })?;

    if connection.incoming.is_empty() {
      return Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "no bytes to read",
      ));
    }

    let mut byte_read_count = 0;
    let (head, tail) = connection.incoming.as_slices();

    // Read head first, make sure we don't overflow the given buffer
    let hread_count = std::cmp::min(buf.len(), head.len());
    buf.copy_from_slice(&head[..hread_count]);
    byte_read_count += hread_count;

    // Now read the tail of deque
    let tread_count = std::cmp::min(buf.len() - hread_count, tail.len());
    buf.copy_from_slice(&tail[..tread_count]);
    byte_read_count += tread_count;

    drop(connection.incoming.drain(..byte_read_count));

    return Ok(byte_read_count);
  }
}

impl Write for TcpStream {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    // TODO: Copied from read, adjust for Write operation
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();
    let connection = connection_manager
      .connection_by_quad
      .get_mut(&self.quad)
      .ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::ConnectionAborted,
          "stream was terminated unexpectedly",
        )
      })?;

    if connection.outgoing.len() >= SENDQUEUE_SIZE {
      return Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "too many bytes buffered",
      ));
    }

    let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - connection.outgoing.len());
    connection.outgoing.extend(&buf[..nwrite]);

    // TODO: Wake up writer

    return Ok(nwrite);
  }

  fn flush(&mut self) -> io::Result<()> {
    // TODO: Copied from read, adjust for Write operation
    let mut connection_manager = self.interface_handle.connection_manager.lock().unwrap();
    let connection = connection_manager
      .connection_by_quad
      .get_mut(&self.quad)
      .ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::ConnectionAborted,
          "stream was terminated unexpectedly",
        )
      })?;

    if connection.outgoing.is_empty() {
      return Ok(());
    } else {
      return Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "too many bytes buffered",
      ));
    }
  }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
  pub src: (Ipv4Addr, u16), // (ip address, port)
  pub dst: (Ipv4Addr, u16),
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

  pub(crate) incoming: VecDeque<u8>,
  pub(crate) outgoing: VecDeque<u8>,
}

impl TcpConnection {
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

  pub fn on_packet<'a>(
    &mut self,
    nic: &tun_tap::Iface,
    iph: etherparse::Ipv4HeaderSlice<'a>,
    tcph: etherparse::TcpHeaderSlice<'a>,
    data: &'a [u8],
  ) -> io::Result<()> {
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
      return Ok(());
    }

    self.recv.nxt = seq_number.wrapping_add(slen);

    if !tcph.ack() {
      eprintln!("NO ACK flag set, will return");
      return Ok(());
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
      if !is_between_wrapped(self.send.una, ack_number, self.send.nxt.wrapping_add(1)) {
        return Ok(());
      }

      self.send.una = ack_number;

      // TODO: will take a look again later

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

    return Ok(());
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
