use std::collections::hash_map::Entry;
use std::io::Read;
use std::thread;

fn main() -> std::io::Result<()> {
  let mut interface = tcp_rust::Interface::new()?;
  let mut l1 = interface.bind(9000)?;

  let jh1 = thread::spawn(move || {
    while let Ok(mut stream) = l1.accept() {
      let mut buf = [0; 512];

      eprintln!("Got connection at port 9000");

      let n = stream.read(&mut buf[..]).unwrap();

      if n == 0 {
        eprintln!("No more data, read {} bytes", n);
      } else {
        eprintln!("Got data {:?} bytes!", &buf[..n]);
      }
    }
  });

  jh1.join().unwrap();
  return Ok(());
}
