mod password;
mod reduction;
mod hash;
mod sha3;
mod generation;
use generation::generation_main;
mod search;
use search::search_main;

use clap::{Parser, Subcommand};
use std::path::PathBuf;


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate the rainbow table
    Generation {
        #[clap(default_value = "./output/")]
        // Path for the output file, default is ./output/
        path: Option<PathBuf>,

        #[clap(long, short = 'm', default_value = "true")]
        /// Use memory file
        /// If the memory file exists, use it to generate the rainbow table
        /// from the last password in the memory file
        /// If the memory file does not exist, generate the rainbow table
        /// and store the last password if the program is stopped
        /// Default is true
        use_mem: bool,

        #[clap(long, short = 'c', default_value = "100")]
        /// Chain length
        /// Chain length must be between 1 and 2048
        /// Default is 100
        /// Chain length is the number of reductions to perform
        /// before storing the password in the memory file
        /// The higher the chain length is, the less memory is used
        /// but the longer it takes to retrieve a password
        /// The lower the chain length is, the more memory is used
        /// but the faster it is to retrieve a password
        chain_length: u16,
    },

    Search {
        #[clap(default_value = "./output/")]
        // Path for the input folder, default is ./output/
        path: PathBuf,

        #[clap(long, short = 'm', default_value = "true")]
        /// Use memory file
        /// If the memory file exists, use it to generate the rainbow table
        /// from the last password in the memory file
        /// If the memory file does not exist, generate the rainbow table
        /// and store the last password if the program is stopped
        /// Default is true
        use_mem: bool,

        #[clap(long, short = 'c', default_value = "100")]
        chain_length: u16,

        #[clap(long)]
        hash: Option<String>,
    
        #[clap(long, short = 'p')]
        hashs_path: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generation { path, use_mem, chain_length } => {
            generation_main(path, use_mem, chain_length);
        },
        Commands::Search { path, use_mem, chain_length, hash, hashs_path} => {
            search_main(path, use_mem, chain_length, hash, hashs_path);
        },
    }
}
