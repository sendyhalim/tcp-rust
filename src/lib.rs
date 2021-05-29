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

mod tcp;

use tcp::*;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
  pub src: (Ipv4Addr, u16), // (ip address, port)
  pub dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct FooBar {
  connection_manager: Mutex<ConnectionManager>,
  pending_var: Condvar,
  rcv_var: Condvar,
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
                let readyAction = map_entry.get_mut().on_packet(
                  &network_interface,
                  ipv4_header,
                  tcp_header,
                  &buf[data_start_index..nbytes],
                )?;

                drop(connection_manager_lock);

                if readyAction.contains(PacketReadyAction::READ) {
                  interface_handle.rcv_var.notify_all();
                }

                if readyAction.contains(PacketReadyAction::WRITE) {
                  // interface_handle.snd_var.notify_all();
                }

                // if let PacketReadyAction::Write | PacketReadyAction::ReadWrite = readyAction {
                // interface_handle.snd_var.notify_all();
                // }
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

    loop {
      let connection = connection_manager
        .connection_by_quad
        .get_mut(&self.quad)
        .ok_or_else(|| {
          io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "stream was terminated unexpectedly",
          )
        })?;

      if connection.is_recv_closed() && connection.incoming.is_empty() {
        // No more data to read and no need to block
        // because there won't be no data in the future because the otherside
        // of TCP already sent FIN at this point.
        return Ok(0);
      }

      if !connection.incoming.is_empty() {
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

      // Need to wait until data is there
      connection_manager = self
        .interface_handle
        .rcv_var
        .wait(connection_manager)
        .unwrap();
    }
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
