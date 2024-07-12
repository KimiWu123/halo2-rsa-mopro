fn main() {
    std::fs::write("./src/mopro.udl", mopro_ffi::app_config::UDL).expect("Failed to write UDL");
    uniffi::generate_scaffolding("./src/mopro.udl").unwrap();
}