# Blockifier Tester

This is a tool created for testing the [Blockifier integrated with Cairo Native](https://github.com/NethermindEth/blockifier). It's current workflow (which could change in the future) is executing a _block range_ from _a_ to _b_. Each block executed can have the following results:

1. A compilation error,
2. a runtime error or
3. a succesfull execution.

Depending on a block output different actionsa are taken. If there was a _compilation error_ it will perform a binary search through the block transactions looking for the culprit. In case of a _runtime error_ or a _succesfull execution_ it will output the block trace allowing the user to check the full behaviour.

## How To

The tool will replay transactions from transaction using Juno with the "Native Blockifier" as its medium. The tool will first run a block using "native" Juno and if there were no crashes (i.e. no compilation errors) it will run that same block with "base" Juno. It will then output a JSON object in the `./results/` directory which will contain a summary of the difference of the traces betweeen both Junos.

### Setup

In the `config.toml` located at the project root set the following variables

```toml
juno_path = "<path to base juno bin>"
juno_native_path = "<path to native juno bin>"
juno_database_path = "<path to juno's db>"
```

To get your base version of Juno you need to first clone the [repo](https://github.com/NethermindEth/juno) repo and build it via `make juno`. Be sure to install all needed dependencies first, which are specified in the that same repository.

Then, to obtain the native version, clone the project again, _switch to branch `native2.6.3-blockifier`_ and recompile.

Finally, Juno requires to be in sync and have Starknet latest blockchain history. To achieve this you can either:

1. Sync Juno manually (around 4 to 5 days in optimal conditions)

2. Manually download a snapshot from [here](https://github.com/NethermindEth/juno). Be sure that the snapshot you are downloading is recent enough.

### Usage

Once setup is complete, build the project with:

```
cargo build
```

and/or directly run it with

```
cargo run
```

## Nice to Have

The tool is a work in progress and is primarily used only during this stage to replay blocks. Nonetheless, there are still a couple of things worth adding:

- [ ] Support for Pathfinder
- [ ] Parallel Juno execution
