mod bpf {
    include!("bpf/api_sentinel.skel.rs");
}

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, MapHandle, RingBufferBuilder,
    TcHookBuilder, TC_EGRESS,
};
use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::os::fd::AsFd;

const MAX_CAPTURE_LEN: usize = 4096;
const CONTROL_SOCK_PATH: &str = "/tmp/api-sentinel.sock";
const BLOCKLIST_PIN_PATH: &str = "/sys/fs/bpf/api_sentinel_blocklist";
const LO_IFINDEX: i32 = 1; 

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
    saddr: u32,   // NEW
    daddr: u32,   // NEW
    sport: u16,   // NEW
    dport: u16,   // NEW
    data: [u8; MAX_CAPTURE_LEN],
}


#[derive(Deserialize)]
struct BlockCmd {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    ttl_ms: u64,
}

fn now_boottime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/* Mirrors make_flow_key() in the BPF program: normalize so either
 * direction of a connection maps to the same key. */
fn make_flow_key_bytes(a1: u32, a2: u32, p1: u16, p2: u16) -> [u8; 12] {
    let (addr_lo, addr_hi, port_lo, port_hi) = if a1 < a2 || (a1 == a2 && p1 < p2) {
        (a1, a2, p1, p2)
    } else {
        (a2, a1, p2, p1)
    };
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&addr_lo.to_ne_bytes());
    buf[4..8].copy_from_slice(&addr_hi.to_ne_bytes());
    buf[8..10].copy_from_slice(&port_lo.to_ne_bytes());
    buf[10..12].copy_from_slice(&port_hi.to_ne_bytes());
    buf
}

fn spawn_control_socket(blocklist_map: Arc<MapHandle>) -> Result<()> {
    let _ = std::fs::remove_file(CONTROL_SOCK_PATH);
    let listener = UnixListener::bind(CONTROL_SOCK_PATH)?;
    std::fs::set_permissions(CONTROL_SOCK_PATH, std::fs::Permissions::from_mode(0o666))?;
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

        let key = make_flow_key_bytes(cmd.saddr, cmd.daddr, cmd.sport, cmd.dport);
        let val = expire_ns.to_ne_bytes();

        match blocklist_map.update(&key, &val, MapFlags::ANY) {
            Ok(_) => eprintln!(
                "[control] blocked flow {}:{} <-> {}:{} ttl_ms={}",
                cmd.saddr, cmd.sport, cmd.daddr, cmd.dport, cmd.ttl_ms
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

  
    let mut tc_builder = TcHookBuilder::new(skel.progs.api_sentinel_egress.as_fd());
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
    let mut egress_hook = tc_builder.hook(TC_EGRESS);
    egress_hook.create()?;
    egress_hook.attach()?;
    eprintln!("TC egress program attached to lo!");

    let _ = std::fs::remove_file(BLOCKLIST_PIN_PATH);
    skel.maps.blocklist.pin(BLOCKLIST_PIN_PATH)?;
    let blocklist_map = Arc::new(MapHandle::from_pinned_path(BLOCKLIST_PIN_PATH)?);
    spawn_control_socket(Arc::clone(&blocklist_map))?;

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
            "saddr": event.saddr,   // NEW
            "daddr": event.daddr,   // NEW
            "sport": event.sport,   // NEW
            "dport": event.dport,   // NEW
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