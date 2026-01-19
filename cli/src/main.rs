fn main() {
    if let Err(e) = nulla_cli::run() {
        eprintln!("nulla-relay error: {:?}", e);
        std::process::exit(1);
    }
}
