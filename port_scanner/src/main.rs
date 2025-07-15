mod port_parser;
mod scanner;

use clap::Parser;
use scanner::PortScanner;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    #[arg(short, long, default_value_t = 100)]
    concurrency: usize,

    #[arg(short = 'T', long, default_value_t = 3000)]
    timeout: u64,

    #[arg(short, long)]
    json: bool,

    #[arg(short, long)]
    banner: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("🔍 Port Scanner v0.1.0");
    println!("Hedef: {}", args.target);
    println!("Portlar: {}", args.ports);
    println!("Paralel bağlantı: {}", args.concurrency);
    println!("Timeout: {}ms", args.timeout);

    match PortScanner::new(args) {
        Ok(scanner) => scanner.run().await,
        Err(e) => {
            eprintln!("Hata: {}", e);
            std::process::exit(1);
        }
    }
}
