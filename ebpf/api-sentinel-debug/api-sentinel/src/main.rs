use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::Parser;
use aya::maps::HashMap;
use std::convert::TryFrom;
use tokio::time::{sleep, Duration};
#[rustfmt::skip]
use log::{debug, warn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/api-sentinel"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("api_sentinel").unwrap().try_into()?;
    // Debug
    println!("Loading classifier...");
    program.load()?;
    println!("Classifier loaded.");

    println!("Attaching classifier to interface: {}", iface);

    program.attach(&iface, TcAttachType::Ingress)?;
    println!("Classifier attached.");
    let counter: HashMap<_, u32, u64> = HashMap::try_from(ebpf.take_map("COUNTER").unwrap())?;
    // Check what Aya sees attached on this interface.
    let (revision, programs) =
    SchedClassifier::query_tcx(&iface, TcAttachType::Ingress)?;

    println!("TCX revision: {}", revision);
    println!("Attached programs: {}", programs.len());

    for program in programs {
        println!("{:?}", program);
   }


    println!("Monitoring packet counter...");

loop {
    let key: u32 = 0;

    match counter.get(&key, 0) {
        Ok(value) => println!("Packets seen: {}", value),
        Err(_) => println!("Packets seen: 0"),
    }

    sleep(Duration::from_secs(1)).await;
}
    Ok(())
}
