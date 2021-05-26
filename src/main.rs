use std::collections::hash_map::Entry;
use std::io::Read;
use std::thread;

fn main() -> std::io::Result<()> {
  let mut interface = tcp_rust::Interface::new()?;
  let mut l1 = interface.bind(9000)?;

  let jh1 = thread::spawn(move || {
    while let Ok(mut stream) = l1.accept() {
      eprintln!("Got connection at port 9000");

      let n = stream.read(&mut [0]).unwrap();

      eprintln!("Got data {} bytes!", n);

      assert_eq!(n, 0);
    }
  });

  jh1.join().unwrap();
  return Ok(());
}
