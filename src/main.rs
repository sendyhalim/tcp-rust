use std::collections::hash_map::Entry;
use std::thread;

fn main() -> std::io::Result<()> {
  let mut interface = tcp_rust::Interface::new()?;
  let mut l1 = interface.bind(9000)?;

  let jh1 = thread::spawn(move || {
    while let Ok(_stream) = l1.accept() {
      eprint!("Got connection at port 9000");
    }
  });

  jh1.join().unwrap();
  return Ok(());
}
