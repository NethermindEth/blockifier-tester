# Blockifier Tester

> ⚠️ **NOTE**: This project goal is to test software which has not yet reached production stage which means setting it up might not be as easy as it should. Please follow the README thoroughly since we tried to add every possible shortcomming to it. If you see there is something missing here that might help with anything please open an issue and we will fix it asap.

This is a tool created for testing the [Blockifier integrated with Cairo Native](https://github.com/NethermindEth/blockifier). It is still a work in progress and currenty it is meant to be used only to assert that _natively compiled contracts_ behaves the same way as _casm compiled contract_.

## Terminology

**Native Juno**: Juno instance running with [Native Blockifier](https://github.com/NethermindEth/blockifier), that is, executing Cairo transactions natively by compiling them first with [Cairo Native](https://github.com/lambdaclass/cairo_native).

**Base Juno**: Juno instance running using the "normal" [Blockifier](https://github.com/starkware-libs/blockifier) or executing Cairo transactions the same way as always, with the VM.

## What it does

The tool takes either a single block or a block range\* (see [Usage](#usage)).
For each block it will:

1. attempt to trace the block with Native Juno
2. if the trace had no failures\*\* then
3. the block will be traced with Base Juno and
4. a comparison between the two results will be written in `./results/trace-<block_number>`.

Otherwise, if there was a failure, the block will be scanned (using binary search) until the faulty transaction is found. The report will be written in `./results/block-<block_number>`.

Please note that everything in `./results/` is being tracked using [Git LFS](#git-lfs) to remove noise from the codebase.

> \*Blocks are sorted in ascending order of how many transactions they have to avoid having to run many long RPC calls before we can get any results.

> \*\*A failure in this case is defined as _any_ of the following:
>
> 1. Juno crashing
> 2. The block is not found (this likely means your Juno database did not have the block)

## Setup

### Dependencies (Juno: base and native)

To get your base version of Juno you need to first clone the [repo](https://github.com/NethermindEth/juno) and build it via `make juno`. Be sure to install all needed dependencies first, which are specified in the that same repository.

Then, to obtain the native version, clone the project again, _switch to `native2.6.3-blockifier` branch_ and recompile. If you haven't compiled Cairo Native before you may face many compilation issues. We suggest you clone [Cairo Native](https://github.com/lambdaclass/cairo_native) and compile it separately first _(be sure to be using the same version as `native2.6.3-blockifier`)_. After both projects are compiled, make sure you have Cairo Native runtime library in your environment which is **essential** for running Ahead of Time Compiled Cairo.

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

## Usage

Once setup is complete, build the project with `cargo build`. The tool presents two commands:

- _**block** `<block_num>`_ which traces and perform comparisons between base and native juno over a single block.
- _**range** `<start_block>` `<end_block>`_ which does the same but over a range of blocks from inclusive `<start_block>` to exclusive `<end_block>`. Note that _(currently)_ blocks are sorted in ascending order by their amount of transactions.
  Execute them with:

```bash
target/cprof/juno_compare_traces block 610508
```

or

```bash
target/cprof/juno_compare_traces range 610508 611000
```

The tester once it runs a block, it won't re-running it again unless the `--run-known` flag is used.
There are some extra options like this for each of these commands. Please be sure to execute `--help` to know about them:

```bash
target/cprof/juno_compare_traces --help
```

> **cprof** stands for compilation profile. It is usually debug or release

> There are some issues with pathing currently. It's advised to run the binary from the project root.

### Logging

The tool will log it's execution. Currently it default to `debug`, but you can set any of the other logging profiles (i.e. `info`, `warn` and `error`) setting the `LOG_LEVEL` variable.

```
LOG_LEVEL=info juno_compare_traces range 610508 611000
```

## Troubleshooting

_Problem_: A block fails on Juno Native when I don't expect it to.

_Suggestion_: Check `juno_out.log` to see what the actual failure was. If the failure was that the block was not found, check `juno_database_path` in your `Config.toml` and make sure it's pointing to a database path that has that block.
