use bindgen::callbacks::{ParseCallbacks, MacroParsingBehavior};
use std::path::PathBuf;

fn main() {

    let bindings = bindgen::Builder::default()
        .header("ffi/systemdefs.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/ffi_bindings.rs file.
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("ffi_bindings.rs"))
        .expect("Couldn't write bindings!");



}
