fn main() {
    libbpf_cargo::SkeletonBuilder::new()
        .source("src/bpf/api_sentinel.bpf.c")
        .clang_args([
            "-I/usr/include/x86_64-linux-gnu",
        ])
        .build_and_generate("src/bpf/api_sentinel.skel.rs")
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/api_sentinel.bpf.c");
}