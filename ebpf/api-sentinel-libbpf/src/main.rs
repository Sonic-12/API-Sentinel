mod bpf {
    include!("bpf/api_sentinel.skel.rs");
}

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, MapHandle, RingBufferBuilder,
};
use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

const MAX_CAPTURE_LEN: usize = 4096;
const CONTROL_SOCK_PATH: &str = "/tmp/api-sentinel.sock";
const BLOCKLIST_PIN_PATH: &str = "/sys/fs/bpf/api_sentinel_blocklist";  // NEW

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

#[derive(Deserialize)]
struct BlockCmd {
    block_conn_id: u64,
    ttl_ms: u64,
}

fn now_boottime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn spawn_control_socket(blocklist_map: Arc<MapHandle>) -> Result<()> {
    let _ = std::fs::remove_file(CONTROL_SOCK_PATH);
    let listener = UnixListener::bind(CONTROL_SOCK_PATH)?;
    eprintln!("Control socket listening at {}", CONTROL_SOCK_PATH);

    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let bl = Arc::clone(&blocklist_map);
            std::thread::spawn(move || handle_control_conn(stream, bl));
        }
    });

    Ok(())
}

fn handle_control_conn(stream: std::os::unix::net::UnixStream, blocklist_map: Arc<MapHandle>) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }

        let cmd: BlockCmd = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[control] bad command '{}': {}", line, e);
                continue;
            }
        };

        let expire_ns: u64 = if cmd.ttl_ms == 0 {
            0
        } else {
            now_boottime_ns() + cmd.ttl_ms * 1_000_000
        };

        let key = cmd.block_conn_id.to_ne_bytes();
        let val = expire_ns.to_ne_bytes();

        match blocklist_map.update(&key, &val, MapFlags::ANY) {
            Ok(_) => eprintln!(
                "[control] blocked conn_id={} ttl_ms={}",
                cmd.block_conn_id, cmd.ttl_ms
            ),
            Err(e) => eprintln!("[control] map update failed: {}", e),
        }
    }
}

fn main() -> Result<()> {
    eprintln!("Opening BPF skeleton...");

    let builder = bpf::ApiSentinelSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    eprintln!("BPF loaded successfully!");

    let _link = skel.progs.api_sentinel.attach()?;
    let _recv_entry_link = skel.progs.api_sentinel_recv_entry.attach()?;
    let _recv_exit_link = skel.progs.api_sentinel_recv_exit.attach()?;

    eprintln!("kprobes attached!");

    /* --- NEW: pin the blocklist map so it's an independent kernel
     * object, then reopen it as an owned MapHandle. This sidesteps the
     * MapImpl-borrows-from-skel lifetime problem entirely — the handle
     * we hand to the control thread has no relationship to `skel`. */
    let _ = std::fs::remove_file(BLOCKLIST_PIN_PATH); // clear stale pin from a prior run
    skel.maps.blocklist.pin(BLOCKLIST_PIN_PATH)?;
    let blocklist_map = Arc::new(MapHandle::from_pinned_path(BLOCKLIST_PIN_PATH)?);
    spawn_control_socket(Arc::clone(&blocklist_map))?;
    /* --- end NEW --- */

    let mut rb_builder = RingBufferBuilder::new();

    rb_builder.add(&skel.maps.events, move |data| {
        if data.len() != std::mem::size_of::<Event>() {
            return 0;
        }

        let event = unsafe { &*(data.as_ptr() as *const Event) };

        let comm = String::from_utf8_lossy(&event.comm);
        let comm = comm.trim_end_matches('\0').to_string();

        let payload_len = (event.len as usize).min(event.data.len());
        let payload = &event.data[..payload_len];

        let payload_hex = payload
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let dir = match event.dir {
            1 => "request",
            2 => "blocked",
            _ => "response",
        };

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

        println!("{}", record);

        0
    })?;

    let ringbuf = rb_builder.build()?;

    eprintln!("Listening for events...\n");

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}