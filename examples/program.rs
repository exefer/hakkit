use std::fs::{self, File};
use std::io::Cursor;

use hakkit::Result;
use hakkit::crypto::nca::decrypt_header;
use hakkit::formats::nca::Nca;
use hakkit::keys::KeySet;

fn main() -> Result<()> {
    let mut keys = KeySet::new();
    keys.load_prod_keys(File::open("prod.keys")?)?;

    let program = fs::read("program.nca")?;
    let plaintext = decrypt_header(&program, keys.header_key.as_ref().unwrap());

    let mut cursor = Cursor::new(&plaintext);
    let nca = Nca::parse(&mut cursor)?;

    println!("program id: {:016X}", nca.program_id);

    Ok(())
}
