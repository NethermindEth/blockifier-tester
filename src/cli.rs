use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "juno_compare_traces")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// Enables `SKIP_FEE_CHARGE` mode for simulating transactions.
    #[clap(long)]
    pub skip_fee_charge: bool,
    /// Enables `SKIP_VALIDATE` mode for simulating transactions.
    #[clap(long)]
    pub skip_validate: bool,
    /// Forces action even if an output file (block- or trace-) already exists for block
    #[clap(long)]
    pub run_known: bool,
}

#[derive(Debug, Subcommand)]
#[clap(about = "A tool to test the blockifier with cairo-native using Juno under the hood.")]
pub enum Commands {
    #[command(about = "Traces single block.")]
    Block {
        /// The block number to trace.
        block_num: u64,
    },

    #[command(about = "Traces a range of [start_block_num, end_block_num) blocks.")]
    Range {
        /// The first block number to trace.
        start_block_num: u64,
        /// The last block number to trace (exclusive).
        end_block_num: u64,
    },
}
