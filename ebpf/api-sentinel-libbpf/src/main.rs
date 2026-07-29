mod bpf {
    include!("bpf/api_sentinel.skel.rs");
}

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};
use serde_json::json;
use std::mem::MaybeUninit;


const MAX_CAPTURE_LEN: usize = 4096;

#[repr(C)]
#[derive(Debug)]
struct Event {
    ts: u64,
    conn_id: u64, 
    pid: u32,
    len: u32,        
    dir: u8,       
    truncated: u8,   
    comm: [u8; 16],
    data: [u8; MAX_CAPTURE_LEN],
}

fn main() -> Result<()> {
    eprintln!("Opening BPF skeleton...");

    // Create skeleton builder
    let builder = bpf::ApiSentinelSkelBuilder::default();

    // Allocate memory for the BPF object
    let mut open_object = MaybeUninit::uninit();

    // Open and load the BPF program
    let open_skel = builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    eprintln!("BPF loaded successfully!");

    // Attach kprobe (responses: tcp_sendmsg_locked)
    let _link = skel.progs.api_sentinel.attach()?;

    // Attach kprobe + kretprobe pair (requests: tcp_recvmsg)
    let _recv_entry_link = skel.progs.api_sentinel_recv_entry.attach()?;
    let _recv_exit_link = skel.progs.api_sentinel_recv_exit.attach()?;

    eprintln!("kprobes attached!");

    // Create Ring Buffer
    let mut rb_builder = RingBufferBuilder::new();


    rb_builder.add(&skel.maps.events, move |data| {
        // Ignore malformed events
        if data.len() != std::mem::size_of::<Event>() {
            return 0;
        }

        // Convert raw bytes into Event
        let event = unsafe { &*(data.as_ptr() as *const Event) };

        // Convert process name to UTF-8
        let comm = String::from_utf8_lossy(&event.comm);
        let comm = comm.trim_end_matches('\0').to_string();

        let payload_len = (event.len as usize).min(event.data.len());
        let payload = &event.data[..payload_len];

        let payload_hex = payload
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let dir = if event.dir == 1 { "request" } else { "response" };

        let record = json!({
            "ts_ns": event.ts,
            "conn_id": event.conn_id,
            "pid": event.pid,
            "dir": dir,
            "comm": comm,
            "len": event.len,
            "truncated": event.truncated == 1,
            "payload_hex": payload_hex,
        });

        // One JSON object per line TO stdout, for the parser to consume.
        println!("{}", record);

        0
    })?;

    // Build Ring Buffer
    let ringbuf = rb_builder.build()?;

    eprintln!("Listening for events...\n");

    // Poll forever
    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}