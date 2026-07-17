# API Sentinel eBPF Debug Notes

Date: 17 July 2026

Completed:
- Aya eBPF template setup
- TC classifier implementation
- Kernel loading verification
- TCX attachment verification
- NAT VM network testing

Verified:
- Program visible in bpftool
- Program attached to enp0s3 ingress
- Network traffic captured through tcpdump

Current investigation:
- Aya logger/perf event visibility
- eBPF map counter reading
- (THE BOTH API SENTINEL IS FOR EXPERIMENT PART ONLY AND STILL UNDER DEVELOPNMENT)

Next:
- Verify eBPF map updates
- Test alternative event transport if required