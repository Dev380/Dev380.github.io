+++
title = "Rewriting ping in Rust (am I stupid?)"
date = 2023-07-07
template = "blog.html"
+++

{{ hr(data_content="please read, I promise I'll look idiotic in the middle") }}

Doing something I've wanted to do for a while, and (hopefully) fixing a Rust crate along the way! I've always wanted to create a simple ICMP utility in Rust to practice working with C/C++ interop and the Linux [raw sockets API](https://www.man7.org/linux/man-pages/man7/raw.7.html). I've had this project idea in a while, and when I get sudden bursts of motivation I try to start it. Alas, I run into the same problem each time: no errors are thrown, I believe my ICMP packets are well-formed, but I never receive a reply! Planning to write down my thoughts in a blog helps my systemize my thoughts, so I thought I'd try again after creating this. This time, I will aim to follow a C++ implementation that functions above [layer 3](https://en.wikipedia.org/wiki/Network_layer), and if that works, "lower" my way down to sending raw ethernet frames directly copied to my network card with `AF_PACKET`.

{{ hr(data_content="the strat") }}
I'll be looking at the excellent [SimplePing](https://github.com/quangIO/SimplePing) to help me figure out userspace networking, which works perfectly fine on my system:
```
SimplePing on master via △ v3.26.4 took 4s
❯ sudo build/simpleping 1.1.1.1
[sudo] password for Dev380:
PING 1.1.1.1 (1.1.1.1)
Received reply: seq=1 rrt=8.88096ms
Received reply: seq=2 rrt=6.80691ms
Received reply: seq=3 rrt=6.3636ms
Received reply: seq=4 rrt=6.92877ms
^C⏎
```
Rust is a data-driven language, so I'd like to create structs with all the necessary information to represent IPv4 ICMP packets.
```rust
struct Icmp {
    header: IcmpHeader,
    payload: Vec<u8>,
}

struct IcmpHeader {
    identifier: u16,
    sequence: u16,
}
```
By the way, an ICMP echo request (ping) looks like this:
![ICMP echo header and payload](/images/icmp_echo_format.png)
Read this from left to right, top to bottom. The first two lines (or 8 bytes) are the ICMP header, and the rest is the payload, which can be any arbitrary data to be returned by the server (Windows uses the alphabet, for example). The identifier is used to distinguish between multiple ping programs running from the same IP, and the sequence is used to distinguish between different echo requests sent by the same program, but they can be set to anything.

To be useful, the structs need to be able to be converted into byte slices, so let's implement them here:
```rust
impl Icmp {
    fn as_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        let header = self.header.as_bytes();
        bytes[0..8].copy_from_slice(&header);
        bytes[8..12].copy_from_slice(&self.payload);
        bytes
    }
}

impl IcmpHeader {
    fn as_bytes(&self) -> [u8; 8] {
        let mut header = [0; 8];
        header[0] = ECHO_REQUEST;
        header[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        header[6..8].copy_from_slice(&self.sequence.to_be_bytes());

        // Setting the checksum
        let checksum = internet_checksum::checksum(&header);
        header[2..4].copy_from_slice(&checksum);
        header
    }
}
```
I set the Icmp return type to `[u8;12]`, forcing the data payload size to be 4. I probably should have done it correctly, but I'm just prototyping right now and an actually good ICMP program isn't the point of this toy program anyway. I used the `internet-checksum` crate instead of implementing by own [internet checksum](https://en.wikipedia.org/wiki/Internet_checksum) implementation, because although the implementation is simple (add together each 2 byte pair as a 16 bit integer while allowing overflow, and invert all the bits at the end) the crates [docs](https://docs.rs/internet-checksum/latest/internet_checksum/) claim that many optimizations (I think they even use SIMD) can be made over a naive implementation.

Anyway, here's the fun part: using raw sockets to actually send our ICMP echo. I'll be using the [nix](https://docs.rs/nix/latest/nix/) crate for this because it provides nice, safe wrappers around libc APIs (for example, having to cast around raw pointers to weird types like `sockaddr_in` does not seem applying or very idiomatic to me), unlike the `libc` crate. Everything of interest will be in the `nix::sys::socket` module, and of course, we'll be calling the `socket` function to initialize our raw socket:
```rust
fn main() {
    let icmp_header = IcmpHeader {
        identifier: 69,
        sequence: 420,
    };
    let icmp = Icmp {
        header: icmp_header,
        payload: vec![1,2,3,4]
    };

    let socket = socket::socket(AddressFamily::Inet, SockType::Raw, SockFlag::empty(), SockProtocol).unwrap();
```
First, the header is initialized with random values (it can be any value, so this is fine) and a payload.

{{ hr(data_content="oh no, my crate doesn't support what I want to do") }}
In my [bacon](https://lib.rs/crates/bacon) window (I just learned of this tool, and it's pretty cool), it shows that this didn't compile. That's because `SockProtocol` is a type from the `nix::sys::socket` module, and I was stuck on what its value should be. The main problem here lies in in the `nix` [API conventions](https://github.com/nix-rust/nix/blob/469032433d68841ad098f03aa2b28e81235b8be8/CONVENTIONS.md):

> Enumerations: We represent sets of constants that are intended as mutually exclusive arguments to parameters of functions by enumerations.

Unfortunately, this means that the protocol number (which Linux uses to match what packets we should receive, although that isn't very important for this program), which is a 32 bit C-style integer in the [C API](https://www.man7.org/linux/man-pages/man2/socket.2.html), is just an enum:
![oh no](/images/sockprotocol_enum.png)
Unfortunately, ICMP is not in this enum yet. This is unfortunate, and many people have tried to fix this in the past. Alas, more serious problems have come up than a kid trying to remake `ping`. The protocol value for IPv4 (ie the internet protocol most of use) is not [in this enum](https://github.com/nix-rust/nix/issues/1953) either, its number of 8 being reserved for [netlink](https://github.com/nix-rust/nix/pull/1289). The enum abstraction over what is, ultimately, an integer passed to a syscall has drawn concern over it being impossible for multiple protocols to share a number, and to [implement custom protocol numbers](https://github.com/nix-rust/nix/issues/1903). Unfortunately, when I had the misfortune of dealing with this, it remained unfixed. I would prefer if `SockProtocol` looked like this:
```rust
pub struct SockProtocol(pub i32);

impl SockProtocol {
    pub fn ipv4() -> Self {
        SockProtocol(8)
    }
    pub fn can_bcm() -> Self {
        SockProtocol(2)
    }
    // etc
}
```
Which solves all of these problems, although it deviates from the API conventions found elsewhere in this crate and module. A problem that arises is [semver compatability](https://semver.org/), which mandates that, unless a "major release" is pushed, the API cannot change in a way that will cause any possible previous project to not compile. My [solution](https://github.com/Dev380/nix/blob/int-protocols/src/sys/socket/mod.rs) creates a separate struct, `SockProtocolInt` that allows for any number to be the protocol number, then changes the API to use that instead. Conversion between `SockProtocol` and `SockProtocolInt` is handled such that the compiler will automatically convert between the types for code still using `SockProtocol`. As of writing, my [PR](https://github.com/nix-rust/nix/pull/2068) is not merged yet, so I'll be using my git repo for now:
```toml
-nix = { version = "0.26.2", branch = "int-protocols", features = ["socket", "uio"] }
+nix = { git = "https://github.com/Dev380/nix", branch = "int-protocols", features = ["socket", "uio"] }
```
{{ hr(data_content="back to MY code") }}
After that slight detour, we can finally create a raw socket to send data from an arbitrary protocol into!
```rust
let socket = socket::socket(AddressFamily::Inet, SockType::Raw, SockFlag::empty(), SockProtocolInt(libc::IPPROTO_ICMP)).unwrap();

```
The `Inet` address family tells the kernel that this is an IPv4 socket, and the `Raw` socket type basically means not TCP or UDP. The `SockFlag`s are just configuration options, and the `SockProtocolInt` uses the ICMP protocol number from our fork of `nix`. The ICMP struct from before can be sent:
```
socket::sendto(socket, &icmp.as_bytes(), &SockaddrIn::new(1, 1, 1, 1, 0), MsgFlags::empty()).unwrap();
```
Note that the `SocketaddrIn` is the IP (1.1.1.1) and the port, which is zero for portless protocols like IPv4. For good manners, we should probably close the [file descriptor](https://en.wikipedia.org/wiki/File_descriptor) at the end:
```rust
unistd::close(socket).unwrap();
```
Let's run it!
```
Finished dev [unoptimized + debuginfo] target(s) in 0.19s
Running `target/debug/ping`
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: EPERM', src/main.rs:49:125
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```
Oh yeah, raw sockets need root to run, because it allows malicious programs to read the traffic of other programs and lets them spam malformed packets at random services in an attempt to get you firewalled. Let's try with `sudo -E` (which preserves environment variables that the rust package manager needs)
```
❯ RUST_BACKTRACE=1 sudo -E cargo run
[sudo] password for alexander: 
    Finished dev [unoptimized + debuginfo] target(s) in 0.00s
     Running `target/debug/ping`
Sending [8, 0, 246, 22, 0, 69, 1, 16
```
I've opened [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html) (super useful for network programming) and this is the output:
```
❯ sudo tcpdump icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
21:48:00.235948 IP Dev380 > one.one.one.one: ICMP echo request, id 69, seq 420, length 12
```
Hm, the identifier and sequence number seem to be what the program specifies, and the total length is correct (8 header bytes and 4 data bytes). Yet, it never detects an echo response, unlike `SimplePing`, the C implementation I'm testing against! This is where I got stuck in all my previous attempts. However, when looking at the Wikipedia pages for various ICMP-related stuff, I realized the authors used `tcpdump` in verbose mode - even the command I ran previously told me to use it! So I gave it a try, ran `sudo -E cargo run` again, and...
```
❯ sudo tcpdump icmp -v
21:51:51.873519 IP (tos 0x0, ttl 64, id 52515, offset 0, flags [DF], proto ICMP (1), length 32)
    Dev380 > one.one.one.one: ICMP echo request, id 69, seq 420, length 12 (wrong icmp cksum f616 (->f210)!)
```
{{ hr(data_content="here's where I'm an idiot") }}
*gasp*

My checksum is wrong? There's no way this was the problem the whole time - in the past, I've copied checksum algorithms from [amos, AKA fasterthanlime](https://fasterthanli.me/series/making-our-own-ping/part-12), made my own from the spec, let copilot do it for me and, this time, I even used a third-party crate. After searching around for a bit, I found this image from a [kind person on stack overflow](https://stackoverflow.com/a/20247802):
![how to ACTUALLY calculate a checksum](/images/icmp_checksum_calculation.png)
*gasp #2*

This whole time, I thought the checksum was calculated over the header, when in fact, the data payload should be accounted for too! That's why my checksum is wrong, and my echo request never even reached the server. (Sidenote: confusingly, IPv4 headers only calculate a checksum over their own header, although it makes sense as ICMP is the last layer and the data would not be error-checked by any other layer) Anyway, to calculate a checksum over the data, I'd have to do a weird trick with reference counters that is frequently used in computational graph theory in rust to let `IcmpHeader` reference `Icmp`'s data and vice versa, but it would just be simpler to remove `IcmpHeader` altogether. The revised code just copies the header data logic into `Icmp`:
```rust
struct Icmp {
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

impl Icmp {
    fn as_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0] = ECHO_REQUEST;

        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.payload);

        // Setting the checksum
        let checksum = internet_checksum::checksum(&bytes);
        bytes[2..4].copy_from_slice(&checksum);

        bytes
    }
}
```
And finally, for the first time in my life, a simple networking hello world that I wrote has worked:
```
❯ sudo tcpdump icmp -v
22:03:30.105781 IP (tos 0x0, ttl 64, id 13577, offset 0, flags [DF], proto ICMP (1), length 32)
    Dev380 > one.one.one.one: ICMP echo request, id 69, seq 420, length 12
22:03:30.112345 IP (tos 0x0, ttl 57, id 38608, offset 0, flags [none], proto ICMP (1), length 32)
    one.one.one.one > Dev380: ICMP echo reply, id 69, seq 420, length 12
```

{{ hr(data_content="but we aren't done yet") }}
However, my goal has always been to implement ICMP with the lowest possible before having to physically touch my network card, [OSI layer 2](https://en.wikipedia.org/wiki/Data_link_layer) and using the `AF_PACKET` address type instead of `AF_INET` (or `AddressFamily::Inet` in the `nix` crate). I just started it above the Internet layer because that's what `SimplePing` does and I figured my problem might have come from an error in the headers of previous layers. Now that I know the problem, it's pretty easy to implement all the other layers - just create structs for each of them, encapsulating higher layers, and finally send it through a truly raw socket, with basically direct access to my network card.

So, let's get to it! The IP layer simply attaches a header to the ICMP request, or any other higher-level protocol such as TCP (nested headers seems to be a common theme in networking). An IPv4 header is 20 bytes (usually), so I'll begin by making a "blank header":
```rust
const BLANK_IP_HEADER: [u8; 20] = [69, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
```
You can read more about IPv4 headers [here](https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header), but the interesting fields are these:

- bytes 2-4 [0, 0]: the total length of the packet, including both header and data
- bytes 5-6 [0, 0]: an identification field for fragmentation (when a packet is bigger than 65535 bytes and needs to be split up), which we'll leave at 0 for simplicity
- byte 9 (64): the TTL, or how many devices the packet will pass through before being dropped. It's 128 on windows and usually 64 on linux which is what I'm using
- byte 10 (1): the protocol number (that `nix` had issues with before), which is 1 for ICMP and 6 for TCP
- byte 10-11 [0, 0]: checksum as in ICMP to fill in later (note that this is over just the header and not the data)
- last 8 bytes: the source IP address, then the destination IP

We'll also need an Ipv4 packet struct:
```rust
struct Ipv4 {
    source_ip: [u8; 4],
    dest_ip: [u8; 4],
    payload: Vec<u8>
}
```
The conversion to bytes is similar to ICMP:
```rust
impl Ipv4{
    fn as_bytes(&self) -> Vec<u8> {
        // Header
        let mut bytes = BLANK_IP_HEADER;
        bytes[12..16].copy_from_slice(&self.source_ip);
        bytes[16..20].copy_from_slice(&self.dest_ip);
        // Setting the checksum
        let checksum = internet_checksum::checksum(&bytes);
        bytes[10..12].copy_from_slice(&checksum);

        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());
        bytes
    }
}
```
Finally, we can change the socket to use the ethernet address family and the protocol to IP instead of ICMP.\
```rust
let socket = socket::socket(AddressFamily::Packet, SockType::Datagram, SockFlag::empty(), SockProtocolInt(libc::ETH_P_IP)).unwrap();
```
The address family is AF_PACKET, one level below the IP layer. The `SockType` is a datagram because the [man pages](https://man7.org/linux/man-pages/man7/packet.7.html) state:

> The socket_type is either SOCK_RAW for raw packets including the link-level header or SOCK_DGRAM for cooked packets with the link-level header removed.

The link-level header is the header for the raw packets the kernel sends to a network card, which we haven't implemented yet so it should be omitted. We also need to construct an IP packet to send over the socket:
```rust
    let icmp = Icmp {
        identifier: 69,
        sequence: 420,
        payload: vec![1,2,3,4]
    };
    let ip = Ipv4 {
        source_ip: [192, 168, 50, 161],
        dest_ip: [1, 1, 1, 1],
        payload: icmp.as_bytes()
    };
```
The IP address is my local, private IP and not the one you would see by searching "what is my IP" because of [NAT](https://en.wikipedia.org/wiki/Network_address_translation). On GNU/Linux, you can get the info like this:
```
❯ ip a | grep inet
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
    inet 192.168.50.161/24 brd 192.168.50.255 scope global dynamic noprefixroute wlan0
```
A MAC address is needed because the kernel needs to know which device on the LAN to send a packet to for AF_PACKET. While an IP address tells you where your data should end up, the MAC addres says where the packet should go immediately (ie the router). For this, `nix::sys::socket::LinkAddr` can be used. Unfortunately, they don't provide a safe constructor, so I'll need to convert it with `from_raw` using the format found in `packet(7)`'s man pages':
```
struct sockaddr_ll {
    unsigned short sll_family;   /* Always AF_PACKET */
    unsigned short sll_protocol; /* Physical-layer protocol */
    int            sll_ifindex;  /* Interface number */
    unsigned short sll_hatype;   /* ARP hardware type */
    unsigned char  sll_pkttype;  /* Packet type */
    unsigned char  sll_halen;    /* Length of address */
    unsigned char  sll_addr[8];  /* Physical-layer address */
};
```
Now, here's the confusing part: there's no way to create the `nix::socket::LinkAddr` struct, apart from an unsafe constructor that takes a pointer to a `nix::sockaddr`, which is supposed to be cast from a `libc::sockaddr`. With the help of [afpacket](https://github.com/nyantec/afpacket), I figured out that I'll have to do what one would do in C to get this to work:

1. Create a `libc::sockaddr_storage`, an intermediary type:
```rust
let mut storage: sockaddr_storage = std::mem::zeroed();
```
2. Cast it to a raw pointer of type `sockaddr_ll` so we can set the requisite fields:
```rust
let addr: *mut sockaddr_ll = &mut storage as *mut sockaddr_storage as *mut sockaddr_ll;
```
3. Set the fields we want:
```rust
(*addr).sll_family = libc::AF_PACKET as u16;
(*addr).sll_protocol = (libc::ETH_P_IP as u16).to_be();
(*addr).sll_addr = [4, 212, 196, 26, 11, 168, 0, 0];
(*addr).sll_halen = 6;
(*addr).sll_ifindex = 3;
```
I got the `ifindex` (index of my network card) using `ip link show`, and the `halen` is the length of my router's MAC address (which I got using `ip neigh`).
4. Cast the intermediary `sockaddr_storage` back to the useful `libc::sockaddr`
```rust
let saddr = &storage as *const sockaddr_storage as *const libc::sockaddr;
```
5. Finally, cast the `libc::sockaddr` to a `nix::sockaddr` and return it (note that `nix` does not use `#[repr(C)]` for their `sockaddr`, which is fine for us, but they should really do it for coompatability with `libc`):
```rust
LinkAddr::from_raw(saddr as *const sockaddr, None).unwrap()
```
Creating the AF_PACKET socket and sending the data:
```rust
let mac_address = unsafe {
    let mut storage: sockaddr_storage = std::mem::zeroed();
    let addr: *mut sockaddr_ll = &mut storage as *mut sockaddr_storage as *mut sockaddr_ll;
    (*addr).sll_family = libc::AF_PACKET as u16;
    (*addr).sll_protocol = (libc::ETH_P_IP as u16).to_be();
    (*addr).sll_addr = [4, 212, 196, 26, 11, 168, 0, 0];
    (*addr).sll_halen = 6;
    (*addr).sll_ifindex = 3;
    let saddr = &storage as *const sockaddr_storage as *const libc::sockaddr;
    LinkAddr::from_raw(saddr as *const sockaddr, None).unwrap()
};

let socket = socket::socket(
    AddressFamily::Packet,
    SockType::Datagram,
    SockFlag::empty(),
    SockProtocolInt(libc::ETH_P_IP),
)
.unwrap();
socket::sendto(socket, &ip.as_bytes(), &mac_address, MsgFlags::empty()).unwrap();
```
And, when running the program, `tcpdump` says...
```
11:56:30.737419 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 46: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto ICMP (1), length 32)
    192.168.50.161 > 1.1.1.1: ICMP echo request, id 69, seq 420, length 12 (wrong icmp cksum f616 (->f210)!)
    0x0000:  4500 0020 0000 0000 4001 8592 c0a8 32a1
    0x0010:  0101 0101 0800 f616 0045 01a4 0102 0304
```
Woopsies, it looks like I screwed up when writing the `Icmp` struct, let's fix that:
```rust
impl Icmp {
    fn as_bytes(&self) -> Vec<u8> {
        // Header
        let mut bytes = [0; 8];
        bytes[0] = ECHO_REQUEST;
        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());

        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());

        // Setting the checksum
        let checksum = internet_checksum::checksum(&bytes);
        bytes[2..4].copy_from_slice(&checksum);
        bytes
    }
}
```
I forgot to move the checksum setting part to the very end of the code, silly me.

Anyway, it works now!
```
11:58:18.891549 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 46: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto ICMP (1), length 32)
    192.168.50.161 > 1.1.1.1: ICMP echo request, id 69, seq 420, length 12
    0x0000:  4500 0020 0000 0000 4001 8592 c0a8 32a1
    0x0010:  0101 0101 0800 f210 0045 01a4 0102 0304
11:58:18.897095 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 47327, offset 0, flags [none], proto ICMP (1), length 32)
    1.1.1.1 > 192.168.50.161: ICMP echo reply, id 69, seq 420, length 12
    0x0000:  4500 0020 b8df 0000 3901 d3b2 0101 0101
    0x0010:  c0a8 32a1 0000 fa10 0045 01a4 0102 0304
    0x0020:  0000 0000 0000 0000 0000 0000 0000

```

{{ hr(data_content="one more layer of the onion") }}
One more thing though! We wrote the IPv4/layer 3 headers ourselves. However, there's still one more of abstraction the kernel handles for us - the ethernet/layer 2 headers, which a network card uses to know who to physically send the raw bits to (in most cases, the router). The kernel wrote it for us because, in the `sockaddr_ll` struct, we gave the kernel the network interface number and the router's mac address, which are enough to determine the source and destination mac address. Technically, an ethernet frame (a frame is what a layer 2 packet is called) looks like this:
![Nerd version of an ethernet frame](/images/ethernet_frame_full_structure.png)
However, most of this is unnecessary, as the device driver/network card will deal with the details for us. In fact, it already does some work by translating our ethernet frames into WiFi (802.11) frames. Fasterthanlime's [article](https://fasterthanli.me/series/making-our-own-ping/part-9) gives a better visualization of the ethernet frames we'll actually have to deal with:
![realistic ethernet frame, credit to amos/fasterthanlime](/images/fasterthanlime_ethernet_frame.png)
We'll just have to append a 14 byte header, with 12 bytes for the destination/source MAC addresses and 2 bytes being [8, 0] (0x0800, IPv4's protocol number, in big endian).

As always, we'll need a struct:
```rust
struct Ethernet {
    dest_mac: [u8; 6],
    source_mac: [u8; 6],
    payload: Vec<u8>,
}
```
And a relatively straightforward `as_bytes` method.
```rust
impl Ethernet {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 14];
        // Set IPv4 ethertype
        bytes[12..14].copy_from_slice(&[8, 0]);
        // Copy MAC addresses
        bytes[0..6].copy_from_slice(&self.dest_mac);
        bytes[6..12].copy_from_slice(&self.source_mac);
        // Payload
        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());
        bytes
    }
}
```
There's no checksum this time! It's called the internet checksum and not the ethernet checksum after all.

I can find my WiFi card's MAC address from all the `tcpdump` output I've been looking at, or just by using `ip addr`. 

After constructing an `Ethernet` struct
```rust
let ethernet = Ethernet {
    dest_mac: [4, 212, 196, 26, 11, 168],
    source_mac: [176, 125, 100, 87, 131, 132],
    payload: ip.as_bytes(),
};
```
and switching the socket type to a raw socket, so it expects the ethernet header:
```
let socket = socket::socket(
    AddressFamily::Packet,
    SockType::Raw,
    SockFlag::empty(),
    SockProtocolInt(libc::ETH_P_IP),
)
.unwrap();
```
It should work...
```
12:17:13.792561 b0:7d:64:57:83:84 > 04:d4:c4:1a:0b:a8, ethertype IPv4 (0x0800), length 46: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto ICMP (1), length 32)
    192.168.50.161 > 1.1.1.1: ICMP echo request, id 69, seq 420, length 12
    0x0000:  4500 0020 0000 0000 4001 8592 c0a8 32a1
    0x0010:  0101 0101 0800 f210 0045 01a4 0102 0304
12:17:13.798852 04:d4:c4:1a:0b:a8 > b0:7d:64:57:83:84, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 57, id 50958, offset 0, flags [none], proto ICMP (1), length 32)
    1.1.1.1 > 192.168.50.161: ICMP echo reply, id 69, seq 420, length 12
    0x0000:  4500 0020 c70e 0000 3901 c583 0101 0101
    0x0010:  c0a8 32a1 0000 fa10 0045 01a4 0102 0304
    0x0020:  0000 0000 0000 0000 0000 0000 0000

```
And according to `tcpdump`, it does!

Thanks for reading, don't miss my next article where I'll be making a port scanner with raw sockets :D
