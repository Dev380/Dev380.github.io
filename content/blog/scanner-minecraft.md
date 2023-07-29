+++
title = "Scanning the whole Internet for Minecraft servers"
date = 2023-07-12
template = "blog.html"
+++

*This continues [rewriting ping in rust](blog/rewriting-ping-rust/), please read that first*

Raw sockets are interesting because they bypass most of the overhead of establishing a TCP connection, making efficient scanners possible, such as [masscan](https://github.com/robertdavidgraham/masscan/), that can scan the entire Internet in a reasonable amount of time. Of interest to me is open Minecraft servers - how could one scan the entire Internet for open port 25565 (Minecraft's port) IPs? This idea has been done to death, and many scanners are actively looking for servers on the open Internet right now. However, writing my own in Rust sounds like it would be an interesting experience.

{{ hr(data_content="start by bikeshedding") }}
Before actually doing scanning, I want to parse exclude files. Masscan supports excluding certain IP ranges (requires it, actually) to avoid scanning undesirable targets like 127.0.0.1 and the US military. To do this, the following file format is used:

- Comments start with "#" and are single line, like python
- Each line consists of a regular IP address, one in CIDR notation or a range of IPs (e.g. 1.1.1.1-1.255.255.255)

The singular adddress and ranges are pretty intuitive, but I must confess that I do not know anything about CIDR notation despite seeing it countless times. I found that this explanation helped me a lot:

- take a CIDR, for example 127.0.0.0/8
- Convert the "IP part" to binary:
```
01111111 00000000 00000000 00000000/8
```
- Find the first n bits, where n is the number after the IP. So 8 in this case. Now take those first n (8) bits from the IP.
```
01111111
```
- Every address that starts with these bits is part of the "network mask" specified by the CIDR address 127.0.0.0/8

This format seems simple enough to parse - remove comments, and check each line for a valid IP, CIDR or range. However, I'd like to make it needlessly complicated in order to learn one of the most mysterious concepts for me - parser combinators.

In C, parsers are usually created in the traditional imperative manner, going through a state machine to create its output. However, in Rust, it is more common to use a declarative approach, where an outline of the file to be parsed is specified and the library handles the rest. `nom` is by far the most popular, but I decided to go with `pest` for now. In `pest`, a "formal grammar" needs to be specified in a pseudo-[EBNF](https://en.wikipedia.org/wiki/Extended_Backus%E2%80%93Naur_form) form, which defines the most basic units of a language (e.g. all alphanumeric characters and the plus sign), and ways to combine them to make valid expressions (sort of like regex). Here's the one I came up with for an exclude file:

```pest
octet = { ASCII_DIGIT ~ ASCII_DIGIT? ~ ASCII_DIGIT? }
address = @{ octet ~ "." ~ octet ~ "." ~ octet ~ "." ~ octet }
mask = { ASCII_DIGIT ~ ASCII_DIGIT? }
cidr = { address ~ "/" ~ mask }
range = { address ~ "-" ~ address }
file = { SOI ~ ((cidr | range | address){,1} ~ NEWLINE )* ~ EOI }

WHITESPACE = _{ " " }
COMMENT = _{ "#" ~ (!NEWLINE ~ ANY)* }
```

The first line defines an `octet` as any 3 digit number (not really accurate, but checking if a number is in a range is above `pest`'s pay grade). The `~` means "and then", the `ASCII_DIGIT` means any number from 0 to 9, and the `?` means the preceding symbol is optional. So, this should be read as "an octet is a single digit followed by an optional other digit followed by another optional digit".

An address is defined as 4 octets separated by periods. Note the `@` in front - this means that no whitespace is allowed between the periods and the octets.

A mask (what I call the number after the slash in 127.0.0.0/8) is defined as any two digit number, similarly to octet.

A CIDR is simply an IP address, a slash and a number after.

A range is two IP addresses connected by a dash.

A `file` is the entire thing we'll be parsing - the `SOI` and `EOI` mean start/end of file, and tells `pest` that the whole file must follow this structure or it should fail. The `((cidr | range | address){,1} ~ NEWLINE )**` is similar to regex - each line should contain between 0 and 1 cidrs, ranges, or addresses, and there can be any number of lines.

`WHITESPACE` and `COMMENT` are special variables that `pest` understands to match a single whitespace character os a single comment, and it'll automagically detect those and ignore them.

{{ hr(data_content="parsing 2: actual code") }}
In Rust, we need to use a macro to tell `pest` to generate a parser based on our `excludes.pest` file:
```rust
#[derive(Parser)]
#[grammar = "excludes.pest"]
struct ExcludesParser;
```
This will make the struct a `Parser` based on the grammar file, and will also generate an enum called `Rule` (basically token types that have been matched).

We can parse it and tell it to look for a valid `file`:
```rust
pub fn parse_excludes(excludes: &str) {
    ExcludesParser::parse(Rule::file, excludes)?
```
This gives an iterator of `file`s, which we know will always have one element, namely the parsed file:
```rust
ExcludesParser::parse(Rule::file, excludes)?
    .next()
    .expect("there should be a valid file!")
    .into_inner()
```
The `into_inner` lets us access the tokens within the `file` in the abstract syntax tree structure (i.e., the addresses we are interested in). After filtering out `EOI`s which are matched for some reason:
```rust
ExcludesParser::parse(Rule::file, excludes)?
    .next()
    .expect("there should be a valid file!")
    .into_inner()
    .filter(|pair| pair.as_rule() != Rule::EOI)
```
We can match the parsed lines:
```rust
.map(|pair| match pair.as_rule() {
    Rule::cidr => parse_cidr(pair),
    Rule::range => parse_range(pair),
    Rule::address => parse_address(pair),
```
and deal with each type of excluded IP range separately.

First, let's define an enum for parsed excluded IPs:
```rust
#[derive(Debug)]
pub enum ExcludedIps {
    Cidr(Ipv4Addr, u8),
    Range(Ipv4Addr, Ipv4Addr),
    Address(Ipv4Addr),
}
```

{{ hr(data_content="parsing cidrs") }}
We can use `into_inner` again to go one "level" deeper and get the parts of the CIDR that have matched (the address before the slash, and the number after). Then, we extract those two, parse them into Rust data types and put them in the `Cidr` enum variant (don't worry about the errors for now):
```rust
fn parse_cidr(cidr: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut cidr_iter = cidr.into_inner();
    let ip = cidr_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;
    let mask = cidr_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<u8>()?;

    // Subnet mask is max 32
    if mask > 32 {
        Err(Error::CidrMaskTooLarge(mask))
    } else {
        Ok(ExcludedIps::Cidr(ip, mask))
    }
}
```

{{ hr(data_content="parsing ranges and addresses) }}
Ranges are easy - it's the same as above (use `into_inner` to go one level deeper, and get the first two matched items) but with two IP addresses matched to create a range, rather than an IP address and a number.
```rust
fn parse_range(range: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut range_iter = range.into_inner();
    let ip1 = range_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;
    let ip2 = range_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;

    Ok(ExcludedIps::Range(ip1, ip2))
}
```
Singular IPs are even easier and don't need `into_inner` - just extract the IP address and parse it into a Rust data type:
```rust
fn parse_address(address: Pair<'_, Rule>) -> Result<ExcludedIps> {
    Ok(ExcludedIps::Address(address.as_str().parse::<Ipv4Addr>()?))
}
```
{{ hr(data_content="done parsing, back to networking") }}
Going back to the main parsing function, the `map` call just needs a branch for any `Rule`s that don't match:
```rust
.map(|pair| match pair.as_rule() {
    Rule::cidr => parse_cidr(pair),
    Rule::range => parse_range(pair),
    Rule::address => parse_address(pair),
    _ => Err(Error::InvalidLine(pair.as_str().to_owned())),
})
.try_collect()
```
The `try_collect` turns the iterator of parsed excluded IPs into a vector, throwing an error if any element of the iterator is an `Err`.

By the way, all the errors are automatically converted into a custom error type or part of a custom error type defined using the `thiserror` crate:
```rust
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse:\n{0}")]
    Parsing(#[from] pest::error::Error<Rule>),
    #[error("CIDR mask is greater than 32: {0}")]
    CidrMaskTooLarge(u8),
    #[error("Not an IP address: {0}")]
    NotIp(#[from] AddrParseError),
    #[error("Not a number: {0}")]
    Nan(#[from] ParseIntError),
    #[error("Invalid line: {0}")]
    InvalidLine(String),
    #[error("Parser failed for unknown reason")]
    UnknownFailure
}
```
And the entire file at the end of this is:
```rust
#![allow(clippy::result_large_err)]
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::net::Ipv4Addr;
use thiserror::Error;
use std::net::AddrParseError;
use std::num::ParseIntError;

#[derive(Parser)]
#[grammar = "excludes.pest"]
struct ExcludesParser;

#[derive(Debug)]
pub enum ExcludedIps {
    Cidr(Ipv4Addr, u8),
    Range(Ipv4Addr, Ipv4Addr),
    Address(Ipv4Addr),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse:\n{0}")]
    Parsing(#[from] pest::error::Error<Rule>),
    #[error("CIDR mask is greater than 32: {0}")]
    CidrMaskTooLarge(u8),
    #[error("Not an IP address: {0}")]
    NotIp(#[from] AddrParseError),
    #[error("Not a number: {0}")]
    Nan(#[from] ParseIntError),
    #[error("Invalid line: {0}")]
    InvalidLine(String),
    #[error("Parser failed for unknown reason")]
    UnknownFailure
}

pub fn parse_excludes(excludes: &str) -> Result<Vec<ExcludedIps>> {
    // We can unwrap because at least one file has to match
    ExcludesParser::parse(Rule::file, excludes)?
        .next()
        .expect("there should be a valid file!")
        .into_inner()
        .filter(|pair| pair.as_rule() != Rule::EOI)
        .map(|pair| match pair.as_rule() {
            Rule::cidr => parse_cidr(pair),
            Rule::range => parse_range(pair),
            Rule::address => parse_address(pair),
            _ => Err(Error::InvalidLine(pair.as_str().to_owned())),
        })
        .try_collect()
}


fn parse_cidr(cidr: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut cidr_iter = cidr.into_inner();
    let ip = cidr_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;
    let mask = cidr_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<u8>()?;

    // Subnet mask is max 32
    if mask > 32 {
        Err(Error::CidrMaskTooLarge(mask))
    } else {
        Ok(ExcludedIps::Cidr(ip, mask))
    }
}

fn parse_range(range: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut range_iter = range.into_inner();
    let ip1 = range_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;
    let ip2 = range_iter.next().ok_or(Error::UnknownFailure)?.as_str().parse::<Ipv4Addr>()?;

    Ok(ExcludedIps::Range(ip1, ip2))
}

fn parse_address(address: Pair<'_, Rule>) -> Result<ExcludedIps> {
    Ok(ExcludedIps::Address(address.as_str().parse::<Ipv4Addr>()?))
}
```
After printing out the result of this function on a sample exclude.conf, here's the output:
```rust
...
        Address(
            86.107.32.28,
        ),
        Address(
            93.95.216.59,
        ),
        Address(
            93.95.216.18,
        ),
        Address(
            93.95.216.162,
        ),
        Cidr(
            103.17.20.160,
            29,
        ),
        Range(
            202.91.162.0,
            202.91.175.255,
        ),
        Address(
            167.114.174.127,
        ),
        Cidr(
            200.160.0.0,
            20,
        ),
        Address(
            188.192.251.198,
        ),
    ],
)
```

{{ hr(data_content="i lied before, here is where I'll actually go back to networking") }}
The layer 2 AF_PACKET API is the best fit for this program, as it is the fastest because the kernel does not need to do much except for passing the data to a network driver (see the [ping article](/blog/rewriting-ping-rust/) for more info on raw sockets). So, let's create our socket:
```rust
use nix::{unistd, sys::socket::{socket, AddressFamily, SockFlag, SockType}};

fn main() {
    let socket = socket::socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        None,
    );
    unistd::close(socket).context("Socket close failed")?;
}
```

{{ hr(data_content="i lied again, back to parsing") }}
Unfortunately, to do anything useful with the socket, we need some MAC addresses and interface indices. The `clap` crate is the standard for CLIs in Rust. All you have to do is write a struct defining all your arguments, and it'll generate everything else for you!

Here's the one for this program:
```rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// A program to scan the whole Internet
struct Args {
    /// MAC address of gateway (router)
    #[arg(short, long)]
    mac: MacAddress,
    /// Interface index
    #[arg(short, long)]
    interface: u8,
}

fn main() {
    let args = Args::parse();
    // ...
```
And look what happens when running `jumboscan --help`:
```
A program to scan the whole Internet

Usage: jumboscan --mac <MAC> --interface <INTERFACE>

Options:
  -m, --mac <MAC>              MAC address of gateway (router)
  -i, --interface <INTERFACE>  Interface index
  -h, --help                   Print help
  -V, --version                Print version
```

Now, we just have to create a `MacAddress` struct that implements `FromStr`.
```rust
#[derive(Clone, Copy, Debug)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}
```
Of course, this also means we have to make another grammar for `pest` to parse! Firstly, a MAC address is just a set of bytes, which are two hex characters:
```pest
mac_octet = { ASCII_HEX_DIGIT{2} }
```
There are two formats for MAC addresses [according to IEEE](https://www.ieee802.org/1/files/public/docs2020/yangsters-smansfield-mac-address-format-0420-v01.pdf): separated by colons (IETF format) and separated by hyphens (IEEE format, and preferred because it doesn't look like an IPv6 address). Technically, without any separators is allowed too, but I don't see that a lot in practice. Let's implement the IETF and IEEE versions:

```pest
mac_octet = { ASCII_HEX_DIGIT{2} }
ietf_mac = { (mac_octet ~ ":" ){5} ~ mac_octet }
ieee_mac = { (mac_octet ~ "-"){5} ~ mac_octet }
mac = { SOI ~ ietf_mac | ieee_mac ~ EOI }
```
We've defined a mac address as an IEEE or IETF mac address, which are defined as 6 octets separated by 5 of their respective separators. Now for some code - first we need to be able to decode single octets, using the `hex` crate:
```rust
fn decode_octet(octet: &str) -> Result<u8> {
    let mut res = [0; 1];
    hex::decode_to_slice(octet, &mut res)?;
    Ok(res[0])
}
```
Then we can decode a collection of octets:
```rust
fn from_mac(mut mac: Pairs<'_, Rule>) -> Result<MacAddress> {
    let mut bytes = [0; 6];
    // Should be safe to unwrap because exactly one type of mac address will be matched according to the grammar
    let parts = mac
        .next()
        .expect("exactly one type of mac should have matched")
        .into_inner()
        .map(|octet| decode_octet(octet.as_str()))
        .try_collect::<Vec<_>>()?;
    bytes[0..6].copy_from_slice(&parts[0..6]);
    Ok(MacAddress(bytes))
}
```
And for the `FromStr` implementation that `clap` requires, we'll use `into_inner` to "unwrap" the `mac` into an `ietf_mac` or `ieee_mac`, then pass it to `from_mac`:
```rust
impl FromStr for MacAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        // Should be safe to unwrap since we should have at least one match
        let parsed = MacAddressParse::parse(Rule::mac, s)?
            .next()
            .expect("at least one mac should match");
        from_mac(parsed.into_inner())
    }
}
```
Let's test the parser out:
```
❯ jumboscan --interface 1 --mac 2f:12:12:12:0000
error: invalid value '2f:12:12:12:0000' for '--mac <MAC>': Parsing failed:
 --> 1:1
  |
1 | 2f:12:12:12:0000
  | ^---
  |
  = expected mac

For more information, try '--help'.
```
And with a correct MAC address...
```
❯ jumboscan --interface 1 --mac 2f:12:12:12:00:00
```
It doesn't error! Now, I think we can *finally* return to actual networking

{{ hr(data_content"hello networking, parsing won't be missed") }}
Alright, back to main:
```rust
fn main() {
    let args = Args::parse();

    let socket = socket::socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        None,
    );
}
```
We can bind our socket to the interface and mac address given in the arguments. This will make sure we'll only receive ethernet frames that match the interface and address. As in the previous article, we need to construct a `sockaddr_ll`. Tl;dr, there's a lot of pointer casting magic.

```rust
let bind_addr = unsafe {
    let mut addr_array = [0; 8];
    addr_array[0..6].copy_from_slice(&args.mac.as_bytes());

    let mut storage = std::mem::zeroed::<libc::sockaddr_storage>();
    let addr_pointer = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_ll;
    (*addr_pointer).sll_family = libc::AF_PACKET as u16;
    (*addr_pointer).sll_protocol = libc::ETH_P_IP as u16;
    (*addr_pointer).sll_ifindex = args.interface as i32;
    (*addr_pointer).sll_halen = 6;
    (*addr_pointer).sll_addr = addr_array;
    LinkAddr::from_raw(
        &storage as *const libc::sockaddr_storage as *const socket::sockaddr,
        None,
    )
}
.ok_or(anyhow::Error::msg(
    "Failed to create address object from interface & mac",
))?;
```
TL;DR, make a `sockaddr_storage`, cast it to a `sockaddr_ll` to modify the fields, then cast the `sockaddr_storage` to a `sockaddr`.

Now, we can finally bind the socket:
```rust
socket::bind(socket, &bind_addr).context("Socket binding failed")?;
```
Finally, we need the interface's mac address and IP address to fill out our TCP packet. The correct way to do it would be to use `libc::getifaddrs`, but to make it a bit easier I'll use `default_net` and iterate through all the interfaces to find the source mac and ip:
```rust
let (source_mac, source_ip) = {
    let iface = default_net::get_interfaces()
        .iter()
        .find(|iface| iface.index == args.interface)
        .ok_or(anyhow::Error::msg(
            "Failed to find interface with given index",
        ))?
        .clone();
    (
        iface
            .mac_addr
            .ok_or(anyhow::Error::msg("Interface has no mac address"))?
            .octets(),
        iface
            .ipv4
            .get(0)
            .ok_or(anyhow::Error::msg("Interface has no ipv4 address"))?
            .addr
            .octets(),
    )
};
```
Then we just need a byte array "template" for a TCP syn packet (the first one sent to initialize a connection). It'll be similar to the one in my last article, but instead of ICMP on top of IPv4 it'll be TCP. As in the previous article, we need an ethernet header:
```
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0
```
The first 12 bytes are the 6 byte destination and source MAC addresses respectively (to be filled in later), and the last 2 are 0x0800 in big-endian, which is the protocol number for IPv4. This tells the network interface what device to send the packet to (the router's MAC address) and who it should return to (the interface itself). After that, we'll need the 20-byte IPv4 header:
```
69, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
```
![IPv4 header](/images/ipv4_header.png)
The first byte is always 69, and encodes the IP version (4) and the length of the header in 4-byte "words" (5), and is thus equal to 0x45. The next byte is always 0, and the next two bytes are 40 in big endian, as the length of the IP header + TCP data is 40. The 64 specifies the time-to-live (it gets decremented by 1 each time it passes through another device, and the packet is dropped when it's 0), and the 6 is the protocol number for TCP. The two bytes after the 6 are the checksum, and the rest of the 8 bytes are the source and destination IP addresses respectively.

Finally, the TCP header part:
```
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 250, 240, 0, 0, 0, 0
```
![TCP header](/images/tcp_header.png)
The 80 is the data offset, AKA the size of the TCP header times 16 (because of the 4 reserved bits), measured in 4 byte words as with the IP header length. Unlike the IP header, this is only the length of the header and not the header and data. The 2 is the flag for SYN, which is turned on for the SYN packet. The window size is the same as Linux.

Putting these together, we get a byte array of a blank SYN:
```rust
const BLANK_SYN: [u8; 54] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 250, 240, 0, 0, 0, 0 ];
```
Then, we can fill out info only known at runtime:
```rust
let mut blank_syn = BLANK_SYN;
blank_syn[0..6].copy_from_slice(&args.mac.as_bytes()); // destination MAC
blank_syn[6..12].copy_from_slice(&source_mac); // source MAC
blank_syn[26..30].copy_from_slice(&source_ip); // source IP
blank_syn[34..36].copy_from_slice(&args.source_port.to_be_bytes()); // source TCP port
blank_syn[36..38].copy_from_slice(&args.dest_port.to_be_bytes()); // destination TCP port
```
We can make a function to calculate both the IP and TCP checksums, with the `internet_checksum` crate. First, for IP:
```rust
fn calculate_checksums(packet: &mut [u8]) {
    // IP header
    let ip_checksum = internet_checksum::checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&ip_checksum);
```
TCP is trickier because a "pseudoheader" is attached before the TCP header when the checksum is calculated.
![TCP pseudoheader](/iamges/tcp_pseudoheader.png)
We can manually add bytes to the tcp checksum for the pseudoheader:
```rust
// TCP
let mut tcp_checksum = Checksum::new();
// Pseudoheader = source IP + dest IP + byte of zeros + protocol number (6) + TCP length
// We need to add these bytes first then add the actual TCP header + data
tcp_checksum.add_bytes(&packet[26..30]);
tcp_checksum.add_bytes(&packet[30..34]);
tcp_checksum.add_bytes(&[0, 6]);
tcp_checksum.add_bytes(&((packet[34..].len() as u16).to_be_bytes()));
```
Then add the real TCP header and data to the checksum:
```rust
// Actual TCP stuff here
tcp_checksum.add_bytes(&packet[34..]);
packet[50..52].copy_from_slice(&tcp_checksum.checksum());
```
The whole function looks like this:
```rust
fn calculate_checksums(packet: &mut [u8]) {
    // IP header
    let ip_checksum = internet_checksum::checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&ip_checksum);

    // TCP
    let mut tcp_checksum = Checksum::new();
    // Pseudoheader = source IP + dest IP + byte of zeros + protocol number (6) + TCP length
    // We need to add these bytes first then add the actual TCP header + data
    tcp_checksum.add_bytes(&packet[26..30]);
    tcp_checksum.add_bytes(&packet[30..34]);
    tcp_checksum.add_bytes(&[0, 6]);
    tcp_checksum.add_bytes(&((packet[34..].len() as u16).to_be_bytes()));
    // Actual TCP stuff here
    tcp_checksum.add_bytes(&packet[34..]);
    packet[50..52].copy_from_slice(&tcp_checksum.checksum());
}
```
And now we can make a function to create a SYN packet given a template and a destination IP:
```rust
fn create_syn(blank_syn: &mut [u8], dest_ip: [u8; 4]) {
    blank_syn[30..34].copy_from_slice(&dest_ip);
    calculate_checksums(blank_syn);
}
```
Finally, we can send our first SYN!
```rust
// in main
let mut syn = blank_syn;
create_syn(&mut syn, [1, 1, 1, 1]);
socket::sendto(socket, &syn, &bind_addr, MsgFlags::empty()).context("Socket send failed")?; 
```
Let's run it (with my router's MAC address from `ip neigh`):
```
❯ sudo jumboscan --interface 3 --mac 04:d4:c4:1a:0b:a8 --source-port 42069 --dest-port 443
```
What does our good friend `tcpdump` have to say? Did it capture our SYN and a SYN-ACK in response?
```
❯ sudo tcpdump -vennSxs 0 tcp and host 1.1.1.1
[sudo] password for Dev380: 
tcpdump: listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:11:42.159793 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.42069 > 1.1.1.1.443: Flags [S], cksum 0x1996 (correct), seq 0, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 a455 01bb 0000 0000 0000 0000
    0x0020:  5002 faf0 1996 0000
14:11:42.168118 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 0, offset 0, flags [DF], proto TCP (6), length 44)
    1.1.1.1.443 > 192.168.50.161.42069: Flags [S.], cksum 0x734b (correct), seq 361527545, ack 1, win 64240, options [mss 1452], length 0
    0x0000:  4500 002c 0000 4000 3906 4c81 0101 0101
    0x0010:  c0a8 32a1 01bb a455 158c 78f9 0000 0001
    0x0020:  6012 faf0 734b 0000 0204 05ac 0000
14:11:43.203299 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 0, offset 0, flags [DF], proto TCP (6), length 44)
    1.1.1.1.443 > 192.168.50.161.42069: Flags [S.], cksum 0x734b (correct), seq 361527545, ack 1, win 64240, options [mss 1452], length 0
    0x0000:  4500 002c 0000 4000 3906 4c81 0101 0101
    0x0010:  c0a8 32a1 01bb a455 158c 78f9 0000 0001
    0x0020:  6012 faf0 734b 0000 0204 05ac 0000
```
It works! Strangly, 1.1.1.1 is sending back two identical SYN-ACKs in response.

{{ hr(data_content="finishing connections (we're still not halfway done after this!)") }}
Now that we are capable of sending SYNs to initiatve them, we need to complete the "embryo", "half-open" or "zombie" connections to send any useful data and get info about Minecraft servers across the Internet (you probably forgot that was the point of all this - don't worry, I did too). TCP has a 3-way handshake model, so connections are established like this:
```
SYN    ---------> server
client <--------- SYN-ACK
ACK    ---------> server
```
After this, the connection is "full-duplexed" amd established. The SYN packet we just built means "synchronize sequence number", which is supposed to tell the server to read the number in the sequence number field of the TCP header (which we set to 0, but should be random according to RFC 1948). The server responds with another header-only packet called SYN-ACK, which has both SYN and ACK flags set and means "we've acknowledged the sequence number you sent". The server gets to choose its own random number to set in the sequence number field, and the acknowledgement field is the client's sequence number plus one. The ACK part of the TCP handshake is sort of a misnomer, since every packet after the initial SYN should have this flag set. The ACK flag just means "we have received all your previous messages, proved by the fact that my acknowledgment number is correct." After this point in the handshake, the connection is "normal" and every packet is an ACK that can carry some data.

{{ hr(data_content="minecraft's protocol: another tiny detour") }}
So, since the end of the TCP 3-way handshake is an ACK packet that can carry data, we should probably decide what data it should carry. This is the traditional layer 7/application layer that anyone implementing a protocol on top of TCP would use (e.g. HTTP). The de facto authority on Minecraft's application layer protocol is [wiki.vg](https://wiki.vg/Server_List_Ping) which has info on the serve list ping protocol that allows us to gather information on Minecraft servers. We'll send a handshake packet in the finished application, but for now we'll use an HTTP GET request to 1.1.1.1:
```
GET / HTTP/1.1
Host: 1.1.1.1
(two newlines here)
```
{{ hr(data_content="the hardest way to make an HTTP request") }}
To complete a TCP connection and send/receive data, we'll need to process packets from the server. As we need to receive at least 2 types of packets from the server (SYN-ACK and the server's response to whatever our request is), we'll need a way to distinguish between different types of server responses, as the real application will receive TCP packets asynchronously from many different servers. Fortunately, the "leave sequence number at 0" shortcut allows for a nice hack: the acknowledgement number of a SYN-ACK will always be 1 (because it's 1 more than the initial sequence number), and the acknowledgement number of the first server response will always be 2 (1 from the SYN-ACK, and ACK = last SYN + 1).

First, let's move all the TCP stuff to `tcp.rs`:
```rust
use internet_checksum::Checksum;

pub fn create_syn(blank_syn: &mut [u8], dest_ip: [u8; 4]) {
    blank_syn[30..34].copy_from_slice(&dest_ip);
    calculate_checksums(blank_syn);
}

fn calculate_checksums(packet: &mut [u8]) {
    // IP header
    let ip_checksum = internet_checksum::checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&ip_checksum);

    // TCP
    let mut tcp_checksum = Checksum::new();
    // Pseudoheader = source IP + dest IP + byte of zeros + protocol number (6) + TCP length
    // We need to add these bytes first then add the actual TCP header + data
    tcp_checksum.add_bytes(&packet[26..30]);
    tcp_checksum.add_bytes(&packet[30..34]);
    tcp_checksum.add_bytes(&[0, 6]);
    tcp_checksum.add_bytes(&((packet[34..].len() as u16).to_be_bytes()));
    // Actual TCP stuff here
    tcp_checksum.add_bytes(&packet[34..]);
    packet[50..52].copy_from_slice(&tcp_checksum.checksum());
}
```
Then, let's initialize the server packet parsing function:
```rust
pub enum ServerPacket {}

pub fn parse_server_packet(server_packet: &[u8], source_port: u16) -> Option<ServerPacket> {
    let received_port = u16::from_be_bytes(
        server_packet[36..38]
            .try_into()
            .expect("36..38 should be [u8; 2]"),
    );
    if received_port != source_port {
        return None;
    }
}
```
We're first checking to see if the destination port is the same as our source port, to avoid colliding with other applications on the same device that are using TCP. Linux doesn't use really high port numbers for automatically generated source ports, so we can just use one of those to make sure no collisions occur and we don't intercept packets meant for other applications.

Since we're using acknowledgement numbers to identify packet types, let's extract that:
```rust
let acknowledgement_number = u32::from_be_bytes(
    server_packet[42..46]
        .try_into()
        .expect("42..46 should be [u8; 4]"),
);
```
Then, let's make a new enum variant for a syn-ack, and match that:
```rust
pub enum ServerPacket {
    SynAck,
}
// ...
// in parse_server_packet
match acknowledgement_number {
    1 => Some(ServerPacket::SynAck),
    2 => { todo!() },
    _ => None,
}
```
An acknowledgement number of 3 means that the server is responding with data after an ACK. This is a bit weird to process, because of something I skipped over when discussing IP and TCP headers...

The first byte of an IPv4 header is 69 because I hardcoded the length of the header at 5 words, or 20 bytes. However, if there are more words, then optional fields aptly named "options" can be used. For numerous reasons, these are used infrequently in IPv4. However, TCP has options too, and those are more commonly used (e.g. Linux adds a timestamp as an option field). This is why the TCP header length field is also called a data offset - we need to add this offset to the length of the ethernet + ip headers in order to see when the data actually starts.
```rust
2 => {
    let mut data_offset = server_packet[46];
    data_offset >>= 4;
},
```
Recall that the data offset field is shifted 4 bits to the left because it is followed by 4 "reserved" bits - this is why we need to shift it back to correct for this.

Now, we just need to update `ServerPacket`:
```rust
pub enum ServerPacket {
    SynAck,
    Data(Vec<u8>), // new!
}
```
And process the data!
```rust
2 => {
    const ETH_IP_HEADERS_LEN: usize = 34;
    let mut data_offset = server_packet[46] as usize;
    data_offset >>= 4;
    Some(ServerPacket::Data(server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec()))
}
```
One minor flaw - array indexing/slicing in rust implicitly panics when the index is out of bounds, which could be a security flaw. Let's add a check for that:
```rust
const ETH_IP_HEADERS_LEN: usize = 34;
const MIN_TCP_HEADER_LEN: usize = 20;
pub fn parse_server_packet(server_packet: &[u8], source_port: u16) -> Option<ServerPacket> {
    if server_packet.len() < ETH_IP_HEADERS_LEN + MIN_TCP_HEADER_LEN {
        return None;
    }
```
And another check when matching a data packet to make sure the data offset is correct:
```rust
2 => {
    let mut data_offset = server_packet[46] as usize;
    data_offset >>= 4;

    // new!
    if server_packet.len() < ETH_IP_HEADERS_LEN + data_offset {
        return None;
    }

    Some(ServerPacket::Data(server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec()))
}
`

Now, we just have to test it! In `main.rs`, let's read packets in an infinite loop, and pass them to `parse_server_packet`. If it's successful and returns a `Some`, we can print out the result:
```rust
const MAX_PACKET_SIZE: usize = 65536;
let mut recv_buffer = [0; MAX_PACKET_SIZE];
loop {
    let read_bytes = unistd::read(socket, &mut recv_buffer).context("Socket read failed")?;
    if let Some(server_packet) = tcp::parse_server_packet(&recv_buffer[14..read_bytes], args.source_port) {
        println!("{server_packet:?}");
    }
}
```
And running it...
```
(it's just hanging forever)
```
There's nothing there. It's stuck on the first read call.

Let's look through the `afpacket` crate (which also uses raw sockets) to see if it has any clues on why this doesn't work.
```rust
// afpacket/src/sync.rs lines 67-82
fn bind_by_index(&self, ifindex: i32) -> Result<()> {
    unsafe {
        let mut ss: sockaddr_storage = std::mem::zeroed();
        let sll: *mut sockaddr_ll = &mut ss as *mut sockaddr_storage as *mut sockaddr_ll;
        (*sll).sll_family = AF_PACKET as u16;
        (*sll).sll_protocol = (ETH_P_ALL as u16).to_be();
        (*sll).sll_ifindex = ifindex;

        let sa = (&ss as *const libc::sockaddr_storage) as *const libc::sockaddr;
        let res = libc::bind(self.0, sa, std::mem::size_of::<sockaddr_ll>() as u32);
        if res == -1 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}
```
Oh no, I've made another silly mistake! My code is:
```rust
(*addr_pointer).sll_protocol = libc::ETH_P_IP as u16;
```
I seem to have forgotten to convert the protocol number to big endian, as `afpacket` did. Let's fix that:
```rust
(*addr_pointer).sll_protocol = (libc::ETH_P_IP as u16).to_be();
```
Thanks to `afpacket` for saving me twice from endless frustration in both this article and my previous one. 😌

Now, running it should work...
```
❯ sudo jumboscan --interface 3 --mac 04:d4:c4:1a:0b:a8' --source-port 65535 --dest-port 443
SynAck
SynAck
```
Perfect! We've received two SYN-ACKs, just as `tcpdump` tells us 1.1.1.1 does. Now we need to respond to SYN-ACKs. In order to send an ACK, we need to know the IP and source port of the SYN-ACK packet, so let's make a few changes to the `ServerPacket` returned by `parse_server_packet`:
```rust
// previously ServerPacket
pub enum ServerPacketType {
    SynAck,
    Data(Vec<u8>),
}

// new!
pub struct ServerPacket {
    pub ip: [u8; 4],
    pub port: [u8; 2],
    pub seuqnece_number: u32,
    pub packet_type: ServerPacketType,
}
```
We're leaving the port number as a `[u8; 2]` as a micro-optimization, because if it's a `u16`, it'll have to be converted back into a `[u8; 2]` for sending anyway.

Let's fix `parse_server_packet` to work with the new `ServerPacket`:
```rust
// previously just returned this
let packet_type = match acknowledgement_number {
    1 => Some(ServerPacketType::SynAck),
    2 => {
        let mut data_offset = server_packet[46] as usize;
        data_offset >>= 4;

        if server_packet.len() < ETH_IP_HEADERS_LEN + data_offset {
            return None;
        }

        Some(ServerPacketType::Data(
            server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec(),
        ))
    }
    _ => None,
}?;

// new!
let ip = server_packet[26..30].try_into().expect("26..30 should be [u8; 4]");
let port = server_packet[34..36].try_into().expect("34..36 should be [u8; 2]");
let sequence_number = u32::from_be_bytes(
    server_packet[38..42]
        .try_into()
        .expect("38..42 should be [u8; 4]"),
);
Some(ServerPacket {
    ip,
    port,
    sequence_number,
    packet_type
})
```
We can add some more print statements for debugging:
```rust
// fn main
loop {
    let read_bytes = unistd::read(socket, &mut recv_buffer).context("Socket read failed")?;
    let packet = tcp::parse_server_packet(&recv_buffer[0..read_bytes], args.source_port);

    if let Some(packet) = packet {
        println!("type: {:?}", packet.packet_type);
        println!("ip: {:?}", packet.ip);
        println!("port: {:?}", packet.port);
        println!("seq: {:?}", packet.sequence_number);
    }
}
```

Let's make a template byte array for an ACK now. It'll be the exact same as a SYN packet, but with the TCP flag set to ACK (16) instead of SYN (2). Also, since we send sequence numbers of 0 in SYNs, our next packet should have a sequence number of 1.
```rust
let mut blank_ack = blank_syn;
// Set TCP flags to ACK
blank_ack[47] = 16;
// Set sequence number to 1
blank_ack[38..42].copy_from_slice(&1u32.to_be_bytes());
```
Also, the `create_syn` function to create a new SYN packet works for an ACK too, so let's rename it:
```diff
- pub fn create_syn(blank_syn: &mut [u8], dest_ip: [u8; 4]) {
-   blank_syn[30..34].copy_from_slice(&dest_ip);
-   calculate_checksums(blank_syn);
- }

+ pub fn create_tcp_packet(blank_packet: &mut [u8], dest_ip: [u8; 4]) {
+   blank_packet[30..34].copy_from_slice(&dest_ip);
+   calculate_checksums(blank_packet);
+ }
```
Finally, send an ACK in response to SYN-ACKs
```rust
if let Some(packet) = packet {
    println!("type: {:?}", packet.packet_type);
    println!("ip: {:?}", packet.ip);
    println!("port: {:?}", packet.port);
    println!("seq: {:?}", packet.sequence_number);

    if packet.packet_type == ServerPacketType::SynAck {
        let mut ack = blank_ack;
        // Copy the sequence number from the SYN-ACK packet for the acknowledgement
        ack[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());
        tcp::create_tcp_packet(&mut ack, packet.ip);
        socket::sendto(socket, &ack, &bind_addr, MsgFlags::empty())
            .context("Socket send failed")?;
    }
}
```
Let's see if it works with `tcpdump`...
```
❯ sudo tcpdump -vennSxs 0 tcp and host 1.1.1.1
tcpdump: listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
17:33:30.038122 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [S], cksum 0xbdeb (correct), seq 0, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 0000 0000 0000
    0x0020:  5002 faf0 bdeb 0000
17:33:30.043740 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 0, offset 0, flags [DF], proto TCP (6), length 44)
    1.1.1.1.443 > 192.168.50.161.65535: Flags [S.], cksum 0x51cc (correct), seq 1220807574, ack 1, win 64240, options [mss 1452], length 0
    0x0000:  4500 002c 0000 4000 3906 4c81 0101 0101
    0x0010:  c0a8 32a1 01bb ffff 48c4 0b96 0000 0001
        0x0020:  6012 faf0 51cc 0000 0204 05ac 0000
17:33:30.043838 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [.], cksum 0x6980 (correct), ack 1220807575, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 0002 48c4 0b97
    0x0020:  5010 faf0 6980 0000
^C
3 packets captured
3 packets received by filter
0 packets dropped by kernel
```
It does! Nothing happens after, which is a good thing. The server is waiting for us to send data after the connection has been established. Also, unlike last time, there weren't any double SYN-ACKs from the server, so I'm assuming 1.1.1.1 sends another SYN-ACK if it hasn't received an ACK in a while to make sure the packet hasn't been lost. In fact, we can observe the reverse if we send two SYNs with the same data:
```rust
socket::sendto(socket, &syn, &bind_addr, MsgFlags::empty()).context("Socket send failed")?;
```
This will cause the server to only send back one SYN-ACK if we respond with an ACK quickly enough, as it's assuming we're doing the same thing and sending two SYNs for redundancy.

{{ hr(data_content="the most convoluted HTTP GETter, but it actually works now") }}
For a final test of our basic TCP implementation, let's send some data after our ACK. First, let's define what we'll send (an HTTP GET request to 1.1.1.1)
```rust
let payload = "GET / HTTP/1.1\nHost: 1.1.1.1\n\n";
```
Since we modify our ACK packet before sending it by changing the checksum, and the checksum function assumes the checksum field is blank, we'll need to create another copy of the blank ACK before applying the checksum:
```rust
if packet.packet_type == ServerPacketType::SynAck {
    let mut data = blank_ack;
    // Copy the sequence number from the SYN-ACK packet for the acknowledgement
    data[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());
    
    let mut ack = data;
    tcp::create_tcp_packet(&mut ack, packet.ip);
    socket::sendto(socket, &ack, &bind_addr, MsgFlags::empty())
        .context("Socket send failed")?;

    let payload = "GET / HTTP/1.1\nHost: 1.1.1.1\n\n";

}
```
Notice how the data's acknowledgement number is the same as the ACKs - this is because the acknowledgement number identifies the last packet received, which will be the same packet if we send two packets in a row.

The only differences between the ACK and the data are:

- the payload attached to the end
- the length field of the IP header being longer
- the PSH flag is set, which tells the kernel on the server to immediately send the data to whatever the application that is bound to that port is

So we just need to change these fields, then we can send our data packet
```rust
if let Some(packet) = packet {
    println!("type: {:?}", packet.packet_type);
    println!("ip: {:?}", packet.ip);
    println!("port: {:?}", packet.port);
    println!("seq: {:?}", packet.sequence_number);

    if packet.packet_type == ServerPacketType::SynAck {
        let mut data = blank_ack;
        // Copy the sequence number from the SYN-ACK packet for the acknowledgement
        data[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());

        let mut ack = data;
        tcp::create_tcp_packet(&mut ack, packet.ip);
        socket::sendto(socket, &ack, &bind_addr, MsgFlags::empty())
            .context("Socket send failed")?;

        // new!
        let payload = "GET / HTTP/1.1\nHost: 1.1.1.1\n\n";
        let mut data = data.to_vec();
        data.extend(payload.as_bytes());
        // Update length
        data[16..18].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
        // Set TCP flags to ACK (16) and PSH (8)
        data[47] = 16 | 8;
        tcp::create_tcp_packet(&mut data, packet.ip);
        socket::sendto(socket, &data, &bind_addr, MsgFlags::empty())
            .context("Socket send failed")?;
    }
}
```
Let's run it and see what `tcpdump` says:
```
❯ sudo tcpdump -vennSxs 0 tcp and host 1.1.1.1
tcpdump: listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
19:28:42.784289 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [S], cksum 0xbdeb (correct), seq 0, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 0000 0000 0000
    0x0020:  5002 faf0 bdeb 0000
19:28:42.791441 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 0, offset 0, flags [DF], proto TCP (6), length 44)
    1.1.1.1.443 > 192.168.50.161.65535: Flags [S.], cksum 0x1300 (correct), seq 1858217060, ack 1, win 64240, options [mss 1452], length 0
    0x0000:  4500 002c 0000 4000 3906 4c81 0101 0101
    0x0010:  c0a8 32a1 01bb ffff 6ec2 2464 0000 0001
    0x0020:  6012 faf0 1300 0000 0204 05ac 0000
19:28:42.791578 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [.], cksum 0x2ab5 (correct), ack 1858217061, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 0001 6ec2 2465
    0x0020:  5010 faf0 2ab5 0000
19:28:42.791612 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 84: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 70)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [P.], cksum 0xc33d (correct), seq 1:31, ack 1858217061, win 64240, length 30
    0x0000:  4500 0046 0000 0000 4006 8567 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 0001 6ec2 2465
    0x0020:  5018 faf0 c33d 0000 4745 5420 2f20 4854
    0x0030:  5450 2f31 2e31 0a48 6f73 743a 2031 2e31
    0x0040:  2e31 2e31 0a0a
19:28:42.799292 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 32422, offset 0, flags [DF], proto TCP (6), length 40)
    1.1.1.1.443 > 192.168.50.161.65535: Flags [.], cksum 0x2c5f (correct), ack 31, win 63784, length 0
    0x0000:  4500 0028 7ea6 4000 3906 cdde 0101 0101
    0x0010:  c0a8 32a1 01bb ffff 6ec2 2465 0000 001f
    0x0020:  5010 f928 2c5f 0000 0000 0000 0000
19:28:42.799747 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 468: (tos 0x0, ttl 57, id 32423, offset 0, flags [DF], proto TCP (6), length 454)
    1.1.1.1.443 > 192.168.50.161.65535: Flags [P.], cksum 0x894e (correct), seq 1858217061:1858217475, ack 31, win 63784, length 414
    0x0000:  4500 01c6 7ea7 4000 3906 cc3f 0101 0101
    0x0010:  c0a8 32a1 01bb ffff 6ec2 2465 0000 001f
    0x0020:  5018 f928 894e 0000 4854 5450 2f31 2e31
    0x0030:  2034 3030 2042 6164 2052 6571 7565 7374
    0x0040:  0d0a 5365 7276 6572 3a20 636c 6f75 6466
    0x0050:  6c61 7265 0d0a 4461 7465 3a20 5765 642c
    0x0060:  2031 3220 4a75 6c20 3230 3233 2032 333a
    0x0070:  3238 3a34 3220 474d 540d 0a43 6f6e 7465
    0x0080:  6e74 2d54 7970 653a 2074 6578 742f 6874
    0x0090:  6d6c 0d0a 436f 6e74 656e 742d 4c65 6e67
    0x00a0:  7468 3a20 3235 330d 0a43 6f6e 6e65 6374
    0x00b0:  696f 6e3a 2063 6c6f 7365 0d0a 4346 2d52
    0x00c0:  4159 3a20 2d0d 0a0d 0a3c 6874 6d6c 3e0d
    0x00d0:  0a3c 6865 6164 3e3c 7469 746c 653e 3430
    0x00e0:  3020 5468 6520 706c 6169 6e20 4854 5450
    0x00f0:  2072 6571 7565 7374 2077 6173 2073 656e
    0x0100:  7420 746f 2048 5454 5053 2070 6f72 743c
    0x0110:  2f74 6974 6c65 3e3c 2f68 6561 643e 0d0a
    0x0120:  3c62 6f64 793e 0d0a 3c63 656e 7465 723e
    0x0130:  3c68 313e 3430 3020 4261 6420 5265 7175
    0x0140:  6573 743c 2f68 313e 3c2f 6365 6e74 6572
    0x0150:  3e0d 0a3c 6365 6e74 6572 3e54 6865 2070
    0x0160:  6c61 696e 2048 5454 5020 7265 7175 6573
    0x0170:  7420 7761 7320 7365 6e74 2074 6f20 4854
    0x0180:  5450 5320 706f 7274 3c2f 6365 6e74 6572
    0x0190:  3e0d 0a3c 6872 3e3c 6365 6e74 6572 3e63
    0x01a0:  6c6f 7564 666c 6172 653c 2f63 656e 7465
    0x01b0:  723e 0d0a 3c2f 626f 6479 3e0d 0a3c 2f68
    0x01c0:  746d 6c3e 0d0a
(this gets repeated for a while)
```
It seems that we are getting an HTTP response from out GET request. Let's see what the hex says...
```
HTTP/1.1 400 Bad Request
Server: cloudflare
Date: Wed, 12 Jul 2023 23:28:42 GMT
Content-Type: text/html
Content-Length: 253
Connection: close
CF-RAY: -

<html>
<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>The plain HTTP request was sent to HTTPS port</center>
<hr><center>cloudflare</center>
</body>
</html>
```
It seems to have worked! Let's check in with our program's output. Recall that it should print out the bytes of the enum variant `ServerPacketType::Data`
```
type: SynAck
ip: [1, 1, 1, 1]
port: [1, 187]
seq: 1858217060
^C⏎
```
Odd. All it outputs is the SYN-ACK, then keeps hanging forever.

{{ hr(data_content="a confession") }}
So, if you look at the `tcpdump` output above closely, you may notice that the server ACKs 31 after we send our GET request. Earlier, I said that the server ACK will always be 2 after we send the first ACK. That isn't necessarily true - the sequence number adds *the TCP payload length* to the received sequence number. This is what the seuqnece number of 1:31 means, and why the server responded with an acknowledgement number of 31 (because the GET request is 30 bytes long). Thus, checking the acknowledgement number won't work, and the code needs to do it in the more proper way of checking the TCP flags.

So, back to `parse_server_packet`:
```rust
let acknowledgement_number = u32::from_be_bytes(
    server_packet[42..46]
        .try_into()
        .expect("42..46 should be [u8; 4]"),
);
let packet_type = match acknowledgement_number {
    1 => Some(ServerPacketType::SynAck),
    3 => {
        let mut data_offset = server_packet[46] as usize;
        data_offset >>= 4;

        if server_packet.len() < ETH_IP_HEADERS_LEN + data_offset {
            return None;
        }

        Some(ServerPacketType::Data(
            server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec(),
        ))
    }
    _ => None,
}?;
```
Let's change this to match flags instead:
```rust
const SYN_ACK: u8 = 2 | 16;
const PSH_ACK: u8 = 8 |16;

let flags = server_packet[47];
let packet_type = match flags {
    SYN_ACK => Some(ServerPacketType::SynAck),
    PSH_ACK => {
        let mut data_offset = server_packet[46] as usize;
        data_offset >>= 4;

        if server_packet.len() < ETH_IP_HEADERS_LEN + data_offset {
            return None;
        }

        Some(ServerPacketType::Data(
            server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec(),
        ))
    }
    _ => None,
}?;
```
Also, the output of `tcpdump` shows the server continuously sending the response and trying to close the connection, because we haven't ACKed their data yet. Additionally, in the real application, leaving a half-open connection would be pretty rude to the servers we're scanning for Minecraft servers. Let's fix that by sending a packet with an RST flag (meaning reset, or abruptly terminating a connection without doing a 4-way FIN handshake) to the server. We need to send both RST and ACK or servers may think we made a mistake, and will keep trying to push data to us for a while.

Back in main.rs, let's change the `if packet.packet_type = ServerPacketType::SynAck` into a match statement:
```rust
match packet.packet_type {
    ServerPacketType::SynAck => {
        let mut data = blank_ack;
        // Copy the sequence number from the SYN-ACK packet for the acknowledgement
        data[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());

        let mut ack = data;
        tcp::create_tcp_packet(&mut ack, packet.ip);
        socket::sendto(socket, &ack, &bind_addr, MsgFlags::empty())
            .context("Socket send failed")?;

        let mut data = data.to_vec();
        data.extend(payload.as_bytes());
        // Update length
        data[16..18].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
        // Set TCP flags to ACK (16) and PSH (8)
        data[47] = 16 | 8;
        tcp::create_tcp_packet(&mut data, packet.ip);
        socket::sendto(socket, &data, &bind_addr, MsgFlags::empty())
            .context("Socket send failed")?;
    },
}
```
And now, let's add a branch for `ServerPacketType::Data` that will send a RST
```rust
ServerPacketType::Data(data) => {
    let mut reset = blank_syn;
    // Set TCP flags to RST and ACK
    reset[47] = 4 | 16;
    // Sequence number should be previous sequence number (1) + payload length
    reset[38..42].copy_from_slice(&(1 + payload.len() as u32).to_be_bytes());
    // Acknowledgement number should be server sequence number + server data length
    reset[42..46].copy_from_slice(&(packet.sequence_number + data.len() as u32).to_be_bytes());
    tcp::create_tcp_packet(&mut reset, packet.ip);
    socket::sendto(socket, &reset, &bind_addr, MsgFlags::empty())
        .context("Socket send failed")?;
},
```
Let's run it and see what `tcpdump` has to say:
```
(truncated)
    0x00e0:  3020 5468 6520 706c 6169 6e20 4854 5450
    0x00f0:  2072 6571 7565 7374 2077 6173 2073 656e
    0x0100:  7420 746f 2048 5454 5053 2070 6f72 743c
    0x0110:  2f74 6974 6c65 3e3c 2f68 6561 643e 0d0a
    0x0120:  3c62 6f64 793e 0d0a 3c63 656e 7465 723e
    0x0130:  3c68 313e 3430 3020 4261 6420 5265 7175
    0x0140:  6573 743c 2f68 313e 3c2f 6365 6e74 6572
    0x0150:  3e0d 0a3c 6365 6e74 6572 3e54 6865 2070
    0x0160:  6c61 696e 2048 5454 5020 7265 7175 6573
    0x0170:  7420 7761 7320 7365 6e74 2074 6f20 4854
    0x0180:  5450 5320 706f 7274 3c2f 6365 6e74 6572
    0x0190:  3e0d 0a3c 6872 3e3c 6365 6e74 6572 3e63
    0x01a0:  6c6f 7564 666c 6172 653c 2f63 656e 7465
    0x01b0:  723e 0d0a 3c2f 626f 6479 3e0d 0a3c 2f68
    0x01c0:  746d 6c3e 0d0a
20:11:04.763877 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 16902, offset 0, flags [DF], proto TCP (6), length 40)
    1.1.1.1.443 > 192.168.50.161.65535: Flags [F.], cksum 0xad91 (correct), seq 2921751501, ack 31, win 63784, length 0
    0x0000:  4500 0028 4206 4000 3906 0a7f 0101 0101
    0x0010:  c0a8 32a1 01bb ffff ae26 63cd 0000 001f
    0x0020:  5011 f928 ad91 0000 0000 0000 0000
20:11:04.763958 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.50.161.65535 > 1.1.1.1.443: Flags [R.], cksum 0xabb7 (correct), seq 31, ack 2921751516, win 64240, length 0
    0x0000:  4500 0028 0000 0000 4006 8585 c0a8 32a1
    0x0010:  0101 0101 ffff 01bb 0000 001f ae26 63dc
    0x0020:  5014 faf0 abb7 0000
(nothing else happens)
```
Great! The server has received our RST packet and is not continuing to send us data. And do we get data output on our program this time?
```
type: SynAck
ip: [1, 1, 1, 1]
port: [1, 187]
seq: 2921751086
type: Data([38, 98, 47, 0, 0, 0, 31, 80, 24, 249, 40, 255, 41, 0, 0, 72, 84, 84, 80, 47, 49, 46, 49, 32, 52, 48, 48, 32, 66, 97, 100, 32, 82, 101, 113, 117, 101, 115, 116, 13, 10, 83, 101, 114, 118, 101, 114, 58, 32, 99, 108, 111, 117, 100, 102, 108, 97, 114, 101, 13, 10, 68, 97, 116, 101, 58, 32, 84, 104, 117, 44, 32, 49, 51, 32, 74, 117, 108, 32, 50, 48, 50, 51, 32, 48, 48, 58, 49, 49, 58, 48, 52, 32, 71, 77, 84, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 116, 101, 120, 116, 47, 104, 116, 109, 108, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 76, 101, 110, 103, 116, 104, 58, 32, 50, 53, 51, 13, 10, 67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 99, 108, 111, 115, 101, 13, 10, 67, 70, 45, 82, 65, 89, 58, 32, 45, 13, 10, 13, 10, 60, 104, 116, 109, 108, 62, 13, 10, 60, 104, 101, 97, 100, 62, 60, 116, 105, 116, 108, 101, 62, 52, 48, 48, 32, 84, 104, 101, 32, 112, 108, 97, 105, 110, 32, 72, 84, 84, 80, 32, 114, 101, 113, 117, 101, 115, 116, 32, 119, 97, 115, 32, 115, 101, 110, 116, 32, 116, 111, 32, 72, 84, 84, 80, 83, 32, 112, 111, 114, 116, 60, 47, 116, 105, 116, 108, 101, 62, 60, 47, 104, 101, 97, 100, 62, 13, 10, 60, 98, 111, 100, 121, 62, 13, 10, 60, 99, 101, 110, 116, 101, 114, 62, 60, 104, 49, 62, 52, 48, 48, 32, 66, 97, 100, 32, 82, 101, 113, 117, 101, 115, 116, 60, 47, 104, 49, 62, 60, 47, 99, 101, 110, 116, 101, 114, 62, 13, 10, 60, 99, 101, 110, 116, 101, 114, 62, 84, 104, 101, 32, 112, 108, 97, 105, 110, 32, 72, 84, 84, 80, 32, 114, 101, 113, 117, 101, 115, 116, 32, 119, 97, 115, 32, 115, 101, 110, 116, 32, 116, 111, 32, 72, 84, 84, 80, 83, 32, 112, 111, 114, 116, 60, 47, 99, 101, 110, 116, 101, 114, 62, 13, 10, 60, 104, 114, 62, 60, 99, 101, 110, 116, 101, 114, 62, 99, 108, 111, 117, 100, 102, 108, 97, 114, 101, 60, 47, 99, 101, 110, 116, 101, 114, 62, 13, 10, 60, 47, 98, 111, 100, 121, 62, 13, 10, 60, 47, 104, 116, 109, 108, 62, 13, 10])
ip: [1, 1, 1, 1]
port: [1, 187]
seq: 2921751087
```
Yes we do!

Now that we can make TCP connections and send/receive data, we'll need to implement the other part of our minecraft server scanner - mass scanning servers through spamming SYNs.

{{ hr(data_content="i love spamming") }}
We can copy masscan's architecture for the SYN flood/mass scanning part. Masscan uses a thread to continuously send SYNs to all the hosts we want to scan, and another thread for receiving data. In pseudocode, the scan thread may look like this:
```python
EXCLUDE_LIST = input()
IP_LIST = [[i, j, k, l] for l in range(256) for k in range(256) for j in range(256) for i in range(256)] and not EXCLUDE_LIST

for ip in IP_LIST:
    send_syn(ip)
```
However, there are two problems with this. One is immediately obvious - an IPv4 address is 32 bits, so there are 2^32 possible IPs taking 4 bytes each. Doing the math, this will take 16 GB to store, and it has to fit in RAM. Using [rust-script](https://rust-script.org/) to make the list of all IPs, it indeed crashes:
```rust
❯ rust-script -e 'let mut v = vec![]; for i in 0..256 { for j in 0..256 { for k in 0..256 { for l in 0..256 { v.push([i,j,k,l]); } } } }'

fish: Job 1, 'rust-script -e 'let mut v = vec…' terminated by signal SIGKILL (Forced quit)
```
The solution masscan uses is to construct ranges of IPs from all the IPs not in the exclude list, and calculate an IP from an index. For example, if the range is all IP addresses, and the index is 32, the program would calculate the 32nd IP address and send a SYN to that. Here's the second problem: IP addresses "close" to each other tend to be owned by the same organization, or even running on the same server. For example, the CIDR range 8.0.0.0/8 is owned by the US military. It would certainly scare some organizations if they received many SYNs on all their IPs at once, as it would look like an attack and might get us blocked for spam. Thus, we need to randomize the IPs in the range. Masscan uses a modified version of the DES encryption algorithm called Blackrock that can make a [one-to-one](https://en.wikipedia.org/wiki/Bijection) mapping of indices For example, if you had the numbers 0-65535 in order and passed each number to Blackrock you'd get a list of the exact same numbers but in a random order. This allows for randomly shuffling IPs with our calculate-IPs-from-indices strategy, without storing every IP in memory and randomizing it there.

I have no clue how any encryption algorithm works, but fortunately for me, mat-1 has already [ported it](https://github.com/mat-1/perfect_rand) to Rust! (On the off-chance that you're reading this mat, you probably don't know who I am but you're such an inspiration to me 💖)

Let's ~~steal~~ add his crate for later:
```toml
perfect_rand = { git = "https://github.com/mat-1/perfect_rand/", rev = "725343f" }
```

{{ hr(data_content="exclude ranges - promise this isn't more bikeshedding") }}
To implement the exclude ranges, let's recap on the algorithm. First, convert ranges of IPs to exclude/scan into ranges of integers. (since an IPv4 address can fit into a 32 bit integer) Then:

1. Trim down the range of IPs to scan (without excludes) by checking each exclusion range to see if it starts outside the range and ends inside it, or if it starts within the range and ends outside it.
{{ iimg(src="/images/ranges_trimming_sides.png", alt="Trimming the sides of the IP range with the exclusion ranges") }}
2. Keep doing this until there's nothing left to trim. (ty RShields for pointing out that this is possible)
3. Find a range of excluded IPs that is completely inside the range of IPs to scan after trimming. (i.e. the exclusion range starts after the scanning range and ends before the scanning range) Split the scanning range using this exclusion range and start from step 1 on both of the resulting ranges.
{{ iimg(src="/images/range_split_inside.png", alt="Splitting the scanning range by an exclusion range inside it") }}

Hope that wasn't too confusing! I think this algorithm is O(n^2), which isn't ideal. However, since this only runs once at the start of the program, performance isn't as big of an issue. An faster alternative was suggested by RShields (tysm ily ❤) but I didn't end up using that.
![RShields the based CS overlord](/images/rshields_splitting_algorithm.png)

Let's start implementing the algorithm by moving the `ExcludedIps` struct to a new file:
```rust
// excludes.rs
#[derive(Debug)]
/// IPs to be excluded from a scan
pub enum ExcludedIps {
    Cidr(Ipv4Addr, u8),
    Range(Ipv4Addr, Ipv4Addr),
    Address(Ipv4Addr),
}
```
Now, let's define a `Range` struct and convert parsed IP exclusions to it:
```rust
#[derive(Debug, Clone, Copy)]
/// Inclusive range, start always <= end
pub struct Range {
    pub start: u32,
    pub end: u32,
}

impl ExcludedIps {
    /// Convert excluded IPs to a range of IPs
    pub fn to_range(&self) -> Range {
        match *self {
            ExcludedIps::Cidr(ip, mask) => {
                let mask = (1 << (32 - mask)) -1;
                let start = u32::from(ip) & !(mask);
                let end = start + mask;
                Range { start, end }
            }
            ExcludedIps::Range(ip1, ip2) => {
                let ip1 = u32::from(ip1);
                let ip2 = u32::from(ip2);
                let start = cmp::min(ip1, ip2);
                let end = cmp::max(ip1, ip2);
                Range { start, end }
            }
            ExcludedIps::Address(ip) => {
                let start = u32::from(ip);
                let end = start;
                Range { start, end }
            }
        }
    }
}
```
Finally, we implement the algorithm discussed earlier.
```rust
impl Range {
    /// The ranges of IPs in this range that aren't in the list of exclusion ranges.
    /// Note that the exclusions vector will be modified when running this method.
    pub fn after_excludes(self, mut exclusions: Vec<Range>) -> Vec<Range> {
        if exclusions.is_empty() {
            return vec![self];
        }


        // Trim off exclusion at the edge of of this current range
        let mut current_range = self;
        let mut fully_inside = None;

        // As pointed out by RShields, we can do this multiple times
        let mut indices_to_remove = Vec::with_capacity(exclusions.len());
        let mut done_something = false;
        loop {
            for (i, exclusion) in exclusions.iter().enumerate() {
                if exclusion.start <= current_range.start {
                    current_range.start = cmp::max(current_range.start, exclusion.end + 1);
                    indices_to_remove.push(i);
                    done_something = true;
                }
                else if exclusion.end >= current_range.end {
                    current_range.end = cmp::min(current_range.end, exclusion.start - 1);
                    indices_to_remove.push(i);
                    done_something = true;
                }
                else {
                    // The start of the exclusion and end of the exclusion are inside this range
                    fully_inside = Some(*exclusion);
                }
            }

            if !done_something {
                break;
            }
            done_something = false;
            // Reset because fully inside this time doesn't mean the same for next time
            fully_inside = None;
            // Has to be sorted for funky reasons don't question it
            // Elements are added in ascending order (see above loop) so we flip it
            indices_to_remove.reverse();
            for index in indices_to_remove.drain(..) {
                exclusions.remove(index);
            }
        }


        // Split the range by any exclusion fully inside this range, if one exists
        // Then do recursion
        if let Some(exclusion) = fully_inside {
            let split_range_one = Range {
                start: current_range.start,
                end: exclusion.start - 1,
            };
            let split_range_two = Range {
                start: exclusion.end + 1,
                end: current_range.end,
            };

            let mut ret = Vec::new();
            ret.append(&mut split_range_one.after_excludes(exclusions.clone()));
            ret.append(&mut split_range_two.after_excludes(exclusions.clone()));
            ret
        } else {
            // Check for validity
            if current_range.start <= current_range.end {
                vec![current_range]
            } else {
                vec![]
            }
        }
    }
}
```
Read through the code if you want, but it basically does what I described earlier. A lot of the checks and implementation details were wrong on my first attempt of implementing the range calculation algorithm. I (rightly) didn't trust myself to make a bug-free implementation on my first try. Fortunately, fuzzing can save my horrendous code.

{{ hr(data_content="fuzzing - okay maybe this is bikeshedding") }}
Fuzzing simply takes some random input data and tries it on a function to test for errors, and is used in many applications to automate the discovery of off-by-one errors, weird memory safety bugs, etc. Most fuzzers also have shrinking algorithms which, when they find a bug, find the smallest possible input that can reproduce that bug. The fuzzer I chose is the `proptest` crate, the most popular rust fuzzer currently. It can fuzz any function that takes in arguments of the `Arbitrary` trait, which converts any sequence of bytes to a struct. Let's derive it for a new `Range`- like object:
```rust
#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use proptest_derive::Arbitrary;

    #[derive(Arbitrary, Debug, Clone, Copy)]
    struct TestRange {
        start: u32,
        end: u32,
    }
```
`Arbitrary` is implemented for `Box<[impl Arbitrary]>` so we can use a `Box<[TestRange]` for our excludes, and a regular `TestRange` for the range of IPs to test. We need the start of a range to be less than or equal to the end, which `TestRange` does not guarantee. Let's make sure that's the case first in our fuzzing function:
```rust
proptest! {
    #[test]
    fn range_exclusion_correct(test_range: TestRange, exclusions: Box<[TestRange]>) {
        let range = Range {
            start: cmp::min(test_range.start, test_range.end),
            end: cmp::max(test_range.start, test_range.end),
        };

        let exclusions: Vec<Range> = exclusions.iter().map(|test_range| {
            Range {
                start: cmp::min(test_range.start, test_range.end),
                end: cmp::max(test_range.start, test_range.end),
            }
        }).collect();
```
Now we just have to calculate the scanning range after excluded ranges have been applied, and panic if it's incorrect so `proptest` knows about it!
```rust
proptest! {
    #[test]
    fn range_exclusion_correct(test_range: TestRange, exclusions: Box<[TestRange]>) {
        // omitted
        
        let excluded_ranges = range.after_excludes(exclusions.clone());
        // Test if exclusions are correct
        for exclusion in &exclusions {
            for i in [exclusion.start, exclusion.end] { // Don't test everything for performance reasons
                if in_ranges(i, &excluded_ranges) {
                    panic!("range: {range:#?} - exclusions: {exclusions:#?} - i: {i} - excluded_ranges: {excluded_ranges:#?}");
                }
            }
        }
    }
}


fn in_ranges(i: u32, ranges: &[Range]) -> bool {
    ranges.iter().any(|range| i >= range.start && i <= range.end)
}
```
The fuzzing should run after a normal `cargo test`.

{{ hr(data_content="the minecraft protocol - can't scan minecraft servers without it!") }}
The scanner in `main.rs` currently doesn't do much scanning at all - it just sends an HTTP request.


{{ hr(data_content="future ideas") }}
Assorted thoughts on extending this scanner
- login attempt scans instead of ping scans, in case people start blocking pings
- perhaps scanning CDN IPs is feasible, because one could look through certificate transparency logs to get a list of domains, and try each of them in the hostname field of a Minecraft packet. However, rate limiting could be an issue.
- there are some bugs - a malicious server can spam us response data, and some servers may segment TCP responses. Both can be fixed by storing connection states like masscan.
- this scanner uses parkers to synchronize receive and transmit thread sends - masscan uses channels so all sending happens on the main thread. Still haven't benchmarked which one is faster with crossbeam in Rust.
