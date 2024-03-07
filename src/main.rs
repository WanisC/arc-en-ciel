mod hashage;

use clap::{Parser, Subcommand};

use crate::hashage::Sha3;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hash the given password
    Hashing {
        // Password recovery option
        #[clap(short = 'p', long = "password", long_help = "Store the password")]
        password: String,

        // Block size option
        #[clap(short = 'b', long = "block", long_help = "Choose the block size")]
        block: Option<i32>,

        // Mode option (simple or ratatui)
        #[clap(default_value = "simple")]
        #[clap(short = 'm', long = "mode", long_help = "Choose the mode of the program")]
        mode: Option<String>,

        // Fingerprint option
        #[clap(default_value = "256")]
        #[clap(short = 'f', long = "footprint", long_help = "Size of the footprint")]
        fingerprint: i32
    },

}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Hashing { password, block, mode, fingerprint } => {
            let test = Sha3::new(password, *block, *fingerprint);
            println!("Password: {}", test.password);
            println!("Fingerprint: {}", test.fingerprint);
            println!("Rate of biits: {}", test.r);
            println!("Extra bloc size: {}", test.c);
            println!("Block size: {:?}", test.b); /* je dois faire attention à ce que la taille du bloc est la bonne pour le fingerprint donné */ 
            println!("Mode: {:?}", mode); 
        },
    }
}