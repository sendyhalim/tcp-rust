use std::collections::hash_map::Entry;
use std::thread;

fn main() -> std::io::Result<()> {
  let mut interface = tcp_rust::Interface::new()?;
  let mut l1 = interface.bind(9000)?;
  let mut l2 = interface.bind(9001)?;

  let jh1 = thread::spawn(move || {
    while let Ok(_stream) = l1.accept() {
      eprint!("Got connection at port 9000");
    }
  });

  let jh2 = thread::spawn(move || {
    while let Ok(_stream) = l2.accept() {
      eprintln!("Got connection at port 9001");
    }
  });

  jh1.join().unwrap();
  jh2.join().unwrap();

  return Ok(());
}
