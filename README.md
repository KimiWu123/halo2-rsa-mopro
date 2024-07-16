# Sample Halo2 Mopro Integration Project

This project demonstrates how to integrate the Halo2 adapter into a Rust project for building libraries with Halo2 proofs.

## Building the Project

Make sure you have the pre-requisites installed. You can find the instructions [here](https://zkmopro.org/docs/docs/prerequisites).

After that, you can test the repo using the `cargo test`.

## Generating the Keys

To generate the keys for the Halo2 circuit, you can run the following command:

```sh
cargo run --bin gen-keys
```
The keys will be generated in the `out` folder. 

_Note that for this sample the `proving` and `verifying` keys are empty and instead will be re-generated on the fly when the proof is generated / verified. 
This is due to the limitation in the version of the Halo2 library used in the RSA circuit._

## Building the Library

To build the IOS library run:

```sh
cargo run --bin ios
```

## Integrating with IOS/Android

Please refer to the [Mopro documentation](https://zkmopro.org/docs) for more information on how to integrate the library with IOS and Android.
