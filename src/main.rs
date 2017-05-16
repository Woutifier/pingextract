extern crate pcap;
use pcap::Capture;

extern crate clap;
use clap::{Arg, App};

use std::path::Path;

fn main() {
    // Command line options
    let matches = App::new("Pingextract")
                      .version("1.0")
                      .author("Wouter B. de Vries <wouter@wbdv.nl>")
                      .about("Extracts (specific) ICMP Echo replies from the given PCAP-files \
                              and outputs it in a column-based format")
                      .arg(Arg::with_name("instance")
                               .help("Sets the instance name (first column)")
                               .required(false)
                               .short("i")
                               .long("instance")
                               .takes_value(true)
                               .value_name("INSTANCE"))
                      .arg(Arg::with_name("input files")
                               .help("Input files to read from")
                               .required(true)
                               .value_name("INPUT")
                               .multiple(true))
                      .arg(Arg::with_name("identifier")
                               .help("ICMP Echo Reply identifier to filter on")
                               .required(false)
                               .long("identifier")
                               .takes_value(true)
                               .value_name("IDENTIFIER"))
                      .arg(Arg::with_name("sequence")
                               .help("ICMP Echo Reply sequence to filter on")
                               .long("sequence")
                               .takes_value(true)
                               .value_name("SEQUENCE"))
                      .arg(Arg::with_name("bpf")
                               .help("Additional BPF (e.g. to filter for a specific source or \
                                      target IP")
                               .long("bpf")
                               .takes_value(true)
                               .value_name("BPF"))
                      .get_matches();

    // Set instance name
    let instance = matches.value_of("instance").unwrap_or("not-specified");

    // Mandatory part of BPF
    let mut bpf = "icmp[icmptype] == 0".to_owned();

    // Optional part of BPF
    if let Some(identifier) = matches.value_of("identifier") {
        bpf.push_str(&format!(" and icmp[4:2] == {}", identifier));
    }
    if let Some(sequence) = matches.value_of("sequence") {
        bpf.push_str(&format!(" and icmp[6:2] == {}", sequence));
    }
    if let Some(additional_bpf) = matches.value_of("bpf") {
        bpf.push_str(&format!(" and {}", additional_bpf));
    }

    // Process input files
    for inputfile in matches.values_of("input files").unwrap() {
        let path = Path::new(inputfile);

        let mut capture_handle = Capture::from_file(path).expect("Unable to open capture file");
        capture_handle.filter(&bpf).expect("Invalid BPF");


        while let Ok(packet) = capture_handle.next() {
            let timestamp = packet.header.ts.tv_sec;
            let ip = format!("{}.{}.{}.{}",
                             packet.data[26],
                             packet.data[27],
                             packet.data[28],
                             packet.data[29]);
            let identifier = (packet.data[38] as u16) << 8 | packet.data[39] as u16;
            let sequence = (packet.data[40] as u16) << 8 | packet.data[41] as u16;
            println!("{}|{}|{}|{}|{}",
                     instance,
                     timestamp,
                     ip,
                     identifier,
                     sequence);
        }
    }
}
