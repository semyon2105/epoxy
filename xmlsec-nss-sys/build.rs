use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-lib=nspr4");
    println!("cargo:rustc-link-lib=nss3");
    println!("cargo:rustc-link-lib=xml2");
    println!("cargo:rustc-link-lib=xmlsec1");
    println!("cargo:rustc-link-lib=xmlsec1-nss");

    let bindings = bindgen::Builder::default()
        .header("src/lib.h")
        .clang_arg("-I/usr/include/nspr")
        .clang_arg("-I/usr/include/nss")
        .clang_arg("-I/usr/include/libxml2")
        .clang_arg("-I/usr/include/xmlsec1")
        .blocklist_var("IPPORT_RESERVED")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .wrap_unsafe_ops(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
