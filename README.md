# syscall-sandbox

A default-deny syscall sandbox in Rust.

`src/lib.rs` declares the sandbox API: number tables, the allowlist, audit
entries, and the decision functions. The bodies are left to implement.
`docs/syscalls.md` carries the reference syscall numbering.

```sh
cargo build
cargo test
```
