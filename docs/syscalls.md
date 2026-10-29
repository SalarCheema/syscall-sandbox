# Syscall tables

Reference numbering for the two architectures the sandbox decides for.
Sources: `arch/x86/entry/syscalls/syscall_64.tbl` and
`include/uapi/asm-generic/unistd.h` in the Linux kernel tree.

| name     | x86_64 | aarch64   |
|----------|--------|-----------|
| read     | 0      | 63        |
| write    | 1      | 64        |
| open     | 2      | — (absent)|
| close    | 3      | 57        |
| mmap     | 9      | 222       |
| mprotect | 10     | 226       |
| socket   | 41     | 198       |
| clone    | 56     | 220       |
| execve   | 59     | 221       |
| openat   | 257    | 56        |

Notes:

- `open` has no aarch64 number: the generic table carries no `open`, only
  `openat`. A decision for `open` on aarch64 resolves to nothing.
- Number 56 names two different calls: `clone` on x86_64, `openat` on
  aarch64. A decision reached from the number alone, or from the name
  through the wrong architecture's table, lands on the wrong call.

# Call arguments

`decide` takes the call's raw arguments as `args: &[u64]`. Index layout per
call (Linux ABI order):

| name   | arg0  | arg1 | arg2  |
|--------|-------|------|-------|
| read   | fd    | buf  | count |
| write  | fd    | buf  | count |
| open   | path  | flags| mode  |
| openat | dirfd | path | flags |
| close  | fd    | —    | —     |
| mmap   | addr  | len  | prot  |
| socket | family| type | proto |
| clone  | flags | stack| —     |
| execve | path  | argv | envp  |

An empty slice means the caller passed no arguments.
