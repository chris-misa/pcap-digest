# pcap-digest

Here is a framework for packet-level analysis of pcap files.
The framework can run multiple 'operations' which are defined by two functions `proc` and `final` and a `name` field.
For each running operation, the framework calls `proc` for each packet, passing a nicely parsed record of packet headers, and `final` once all packets have been processed.
The `name` field is used only for identifying particular operations outputs.
Operations are instantiated by operation constructors which take zero or more constructor arguments followed by an output channel and return a record with `proc` and `final` members.
Constructors use closures to encapsulate any state they need to maintain between calls to `proc` and `final`.

# Building

The following packages are needed from opam: cstruct pcap-format ipaddr mmap

Once dependencies are in place, should build with `dune build`.
The main executable ends up called `main.exe` for now (regardless of system).

# Running

The `main.exe` executable takes two arguments: an operation string describing which operations to run and a file path of the pcap file to process.
The operation string is a comma-separated list of operation keys (as defined in `main.ml:ops_map`).
Note that new keys can easily be added by adding to the definition of `main.ml:ops_map` using pre-defined parametric operations.

The output of each operation is written to a separate file whose name is generated by appending ".out" to the operation's command-line key.

Several high-level operations are currently implemented.

## Dump

See `dump.ml`. This operation prints out the timestamp and headers of each packet without any further processing.

Usage: `./main.exe dump <pcap>`

## Total distinct entities

See `totals.ml`. These operations print out a list of all distinct sources or destinations in the pcap file.

Usage: `./main.exe total.srcs <pcap>`

## Windowed operations

See `windows.ml`. Provides support for calling operations over fixed-duration time windows based on timestamps in the pcap file.

Usage : `./main.exe window.dsts` to generate a list of the number of distinct destination IPv4 addresses in each time window.

**Implementation note.** The operation constructor `windows.ml:windows` takes a list of sub-operation constructors (e.g., `windows.ml:srcs`) which it then passes calls to `proc` while resetting these suboperations (calling their `final` and re-constructing them) between time windows.
Sub-operations are expected to write a single value followed by a comma when their `final` is called allowing `windows` to generate a nice comma-separated list of per-window results.

The idea is to allow easy addition of new windowed operations with just a few lines of code describing their per-packet behavior.
