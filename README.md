# todo

See `todo.md`

# Build

If you want to run juno using cairo native, create an executable script `spawn_native_juno.sh` in the root of the project that starts it. Something like the following:
`#!/usr/bin/env bash`
`cd ../../native; ./build/juno --http --disable-sync --db-path ../database`
The specifics will depend on your setup.
If you also want to run juno without cairo native, create a similar script called `spawn_base_juno.sh` that runs the appropriate juno build

Once that's done, just
`cargo build`

# Run

`cargo run`