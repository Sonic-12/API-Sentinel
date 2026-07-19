mod bpf {
    include!("bpf/api_sentinel.skel.rs");
}

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};
use std::mem::MaybeUninit;

// Event received from the eBPF Ring Buffer.
#[repr(C)]
#[derive(Debug)]
struct Event {
    ts: u64,
    pid: u32,
    len: u32,
    comm: [u8; 16],
    data: [u8; 256],
}

fn main() -> Result<()> {
    println!("Opening BPF skeleton...");

    // Create skeleton builder
    let builder = bpf::ApiSentinelSkelBuilder::default();

    // Allocate memory for the BPF object
    let mut open_object = MaybeUninit::uninit();

    // Open and load the BPF program
    let open_skel = builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    println!("BPF loaded successfully!");

    // Attach tracepoint
    let _link = skel.progs.api_sentinel.attach()?;

    println!("kprobe attached!");

    // Create Ring Buffer
    let mut rb_builder = RingBufferBuilder::new();

    rb_builder.add(&skel.maps.events, |data| {
        // Ignore malformed events
        if data.len() != std::mem::size_of::<Event>() {
            return 0;
        }

        // Convert raw bytes into Event
        let event = unsafe {
            &*(data.as_ptr() as *const Event)
        };

        // Convert process name to UTF-8
        let comm = String::from_utf8_lossy(&event.comm);
        let comm = comm.trim_end_matches('\0');

        println!("\n==============================");
        println!("Timestamp : {}", event.ts);
        println!("PID       : {}", event.pid);
        println!("Process   : {}", comm);
        println!("Data Len  : {}", event.len);


        // Raw Payload (HEX)
        let payload_len = (event.len as usize).min(event.data.len());
        let payload = &event.data[..payload_len];

        println!("Raw Payload (HEX):");

        for byte in payload {
            print!("{:02x} ", byte);
        }
        println!();

        // UTF-8 text
        if let Ok(text) = std::str::from_utf8(payload) {
            println!("Payload (TEXT):");
            println!("{}", text);
        } else {
            println!("Payload is not valid UTF-8 (likely encrypted/binary).");
        }

        println!("==============================");

        0
    })?;

    // Build Ring Buffer
    let ringbuf = rb_builder.build()?;

    println!("Listening for events...\n");

    // Poll forever
    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}