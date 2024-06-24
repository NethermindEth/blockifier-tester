# Blockifier Tester

This is a tool created for testing the [Blockifier integrated with Cairo Native](https://github.com/NethermindEth/blockifier).

## Project Status

The tool is a work in progress and is primarily used only during this stage to replay blocks. It currently has no guarantees of stability for any behavior.

## Terminology

Native Juno : Juno instance running with [Native Blockifier](https://github.com/NethermindEth/blockifier) a.k.a. executing Cairo transactions natively, by compiling them with [Cairo Native](https://github.com/lambdaclass/cairo_native).

Base Juno : Juno instance running using the "normal" [Blockifier](https://github.com/starkware-libs/blockifier) a.k.a. executing Cairo transactions with the VM.

## What it does

The tool takes either a single block or a block range\* (see [Usage](#usage)).
For each block it will:
Attempt to trace the block with Native Juno. If the trace had no failures\*\* then the block will be traced with Base Juno and a comparison between the two results will be dumped in `./results/trace-<block_number>`. Otherwise, the block transactions will be simulated and a report will be dumped in `./results/block-<block_number>`. Currently, the block is simulated using a binary search to find which transaction crashes Juno. Results are tracked using [Git LFS](#git-lfs)

> \*Blocks are sorted in ascending order of how many transactions they have to avoid having to run many long RPC calls before we can get any results.

> \*\*A failure in this case is defined as _any_ of the following:
>
> 1. Juno crashing
> 2. The block is not found (this likely means your Juno database did not have the block)

## Setup

### Dependencies (Juno: base and native)

To get your base version of Juno you need to first clone the [repo](https://github.com/NethermindEth/juno) and build it via `make juno`. Be sure to install all needed dependencies first, which are specified in the that same repository.

Then, to obtain the native version, clone the project again, _switch to `native2.6.3-blockifier` branch_ and recompile. If you haven't compile Cairo Native before you may face many compilation issues. We suggest you clone [Cairo Native](https://github.com/lambdaclass/cairo_native) and compile it separately first _(be sure to be using the same version as `native2.6.3-blockifier`)_. After both projects are compiled, make sure you have Cairo Native runtime library in your environment which is essential for running AOT Compiled Cairo.

```
export CAIRO_NATIVE_RUNTIME_LIBRARY=/<absolute_path_to>/cairo_native/target/release/libcairo_native_runtime.a
```

Finally, Juno must be in sync and have Starknet latest blockchain history. To achieve this you can either:

1. (recommended) Manually download a snapshot from [here](https://github.com/NethermindEth/juno). Be sure that the snapshot you are downloading is recent enough.

2. Sync Juno manually (around 4 to 5 days in optimal conditions)

### Config

In the `config.toml` located at the project root set the following variables\*:

```toml
juno_path = "<path to base Juno executable>"
juno_native_path = "<path to native Juno executable>"
juno_database_path = "<path to Juno's database>" # correlates to `--db-path` argument passed to Juno
```

It is recommended that you use absolute paths and avoid `$HOME` and `~`

Example `config.toml`:

```toml
juno_path = "/home/pwhite/repos/juno/build/juno"
juno_native_path = "/home/pwhite/repos/native_juno/build/juno"
juno_database_path = "/home/pwhite/snapshots/juno_mainnet"
```

### Git LFS

To mantain all results in the same repo and use github as a synced db we used Git LFS. It is used to keep track of all files in the `./results/` directory. Follow install instructions [here](https://git-lfs.com/).

### Usage

Once setup is complete, build the project with `cargo build`. The tool presents two commands:

- _**block** `<block_num>`_ which traces and perform comparisons between base and native juno over a single block.
- _**range** `<start_block>` `<end_block>`_ which does the same but over a range of blocks from inclusive `<start_block>` to exclusive `<end_block>`. Note that _(currently)_ blocks are sorted in ascending order by their amount of transactions.

Execute them with:

```bash
cd target/debug # or whatever compilation profile you've used
juno_compare_traces block 610508
```

or

```bash
juno_compare_traces range 610508 611000
```

## Troubleshooting

Problem: A block fails on Juno Native when I don't expect it to.
Suggestion: Check `juno_out.log` to see what the actual failure was. If the failure was that the block was not found, check `juno_database_path` in your `Config.toml` and make sure it's pointing to a database path that has that block.
