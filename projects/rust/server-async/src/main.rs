use clap::Parser;
use rm_server_async::{Service, http};
use std::net::SocketAddr;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7878")]
    address: SocketAddr,
    /// How long a login stays valid, in seconds.
    #[arg(long, default_value_t = rm_server_async::DEFAULT_TOKEN_TTL_SECONDS)]
    token_ttl_seconds: u64,
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    http::run(args.address, Service::new(args.token_ttl_seconds)).await
}
