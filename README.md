# pingextract
[![Build Status](https://travis-ci.org/Woutifier/pingextract.svg?branch=master)](https://travis-ci.org/Woutifier/pingextract)

## Dependencies
- Rust (https://rustup.rs/)
- Libpcap (debian/ubuntu: libpcap0.8 libpcap0.8-dev)

## Build
```
cargo build --release
```

## Commandline options
```USAGE:
    pingextract [OPTIONS] <INPUT>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bpf <BPF>                  Additional BPF (e.g. to filter for a specific source or
                                     target IP
        --identifier <IDENTIFIER>    ICMP Echo Reply identifier to filter on
    -i, --instance <INSTANCE>        Sets the instance name (first column)
        --sequence <SEQUENCE>        ICMP Echo Reply sequence to filter on

ARGS:
    <INPUT>...    Input files to read from
```
