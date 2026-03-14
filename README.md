# Lavender
Lavender is a userspace EDR (Endpoint Detection and Response) tool that I am building from scratch. It will include small security agents written in Rust and C that hook into the Linux kernel via eBPF to detect anomalous behavior. I also plan to add a real-time dashboard that shows threat events.

## How to build
- First, make sure BTF (BPF Type Format) is enabled and available in your kernel.
- Then run:
    ```
     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    ```
    This generates the `vmlinux.h` header file, which is required to access BTF metadata.