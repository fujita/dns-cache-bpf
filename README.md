dns-cache-bpf is an experiment on implementing server software in eBPF, an in-kernel cache for DNS server software. It works transparently for user-space DNS server software.

The eBPF code is implemented in C and the user-space management daemon code is implemented in Rust. [libbpf-rs](https://github.com/libbpf/libbpf-rs) generates a single binary from both code.

The current eBPF code can handle very simple response packet, which including only one answer section. All the current user-space code does is printing some stats periodically; IOW, it can't do anything useful.

The second and subsequent execution of the following command should hit cache if everything goes well:

```bash
$ dig +rec -t a www.google.com @[your server ip]
```
