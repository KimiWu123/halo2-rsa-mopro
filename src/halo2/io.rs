use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use halo2wrong::curves::bn256::Bn256;
use halo2wrong::halo2::poly::commitment::Params;
use halo2wrong::halo2::poly::kzg::commitment::ParamsKZG;

fn with_writer<E>(path: &Path, f: impl FnOnce(&mut BufWriter<File>) -> Result<(), E>)
where
    E: fmt::Debug,
{
    let file = File::create(path).expect("Unable to create file");
    let mut writer = BufWriter::new(file);
    f(&mut writer).expect("Unable to write to file");
    writer.flush().expect("Unable to flush file");
}

fn with_reader<T, E>(path: &Path, f: impl FnOnce(&mut BufReader<File>) -> Result<T, E>) -> T
where
    E: fmt::Debug,
{
    let file = File::open(path).expect("Unable to open file");
    let mut reader = BufReader::new(file);
    f(&mut reader).expect("Unable to read from file")
}

/// Write SRS to file.
pub fn write_srs(srs: &ParamsKZG<Bn256>, path: &Path) {
    with_writer(path, |writer| srs.write(writer));
}

/// Read SRS from file.
pub fn read_srs_path(path: &Path) -> ParamsKZG<Bn256> {
    with_reader(path, |reader| ParamsKZG::read(reader))
}

/// Read SRS from
pub fn read_srs_bytes(data: &[u8]) -> ParamsKZG<Bn256> {
    ParamsKZG::read::<_>(&mut &data[..]).unwrap()
}
