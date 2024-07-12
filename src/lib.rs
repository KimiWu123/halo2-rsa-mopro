mod halo2;

pub use halo2::{prove, verify};

pub use halo2::io;

mopro_ffi::app!();

mopro_ffi::set_halo2_circuits! {
    ("rsa_pk", prove, "rsa_vk", verify),
}