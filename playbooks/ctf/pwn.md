# CTF: Pwn (Binary Exploitation)

Memory-corruption to hijack control flow, usually on a remote service you get a
copy of. Almost always Linux ELF + a `nc host port`. Workflow is highly
standardized — follow it.

## Setup (every pwn challenge)
1. `checksec <bin>` — the mitigations dictate the technique:
   - No canary -> straight stack smash.
   - No PIE -> fixed addresses, easy ROP.
   - No NX -> shellcode on the stack.
   - Partial/Full RELRO -> GOT overwrite viable or not.
2. Identify libc: if a `libc.so` is provided, use it; else leak and ID with the
   libc-database / blukat. Match the loader with `patchelf`/pwninit for local
   testing.
3. Decompile in Ghidra to find the bug and the input path.
4. Template with **pwntools**: `p = process('./bin')` / `remote(host,port)`,
   `context.binary`, cyclic pattern to find the offset.

## Find the offset
`cyclic 200` as input -> crash -> `cyclic_find(<value in RIP/RSP>)` gives the
exact overflow offset. This is step one of nearly every stack challenge.

## Technique ladder (roughly by mitigation)
- **ret2win:** overflow RIP to a `win()`/`give_shell()` already in the binary.
- **ret2shellcode:** NX off + known writable exec buffer -> jump to your shellcode.
- **ret2libc / ret2system:** leak a libc address (via puts/printf of a GOT entry),
  compute base, return into `system("/bin/sh")` or `one_gadget`.
- **ROP chain:** build with `ROPgadget`/`ropper` + pwntools `ROP()`; do `execve`
  via a syscall chain when no libc.
- **Format string** (`printf(user)`): leak stack/canary/addresses with `%p`,
  arbitrary write with `%n` (fmtstr_payload).
- **GOT overwrite** (Partial RELRO): redirect a resolved function to system/win.
- **Heap:** tcache poisoning, fastbin dup, use-after-free, `__free_hook`/
  `__malloc_hook` overwrite (glibc-version dependent), House-of-* for hard ones.

## Bypasses
- **Canary:** leak it (format string / partial overflow / fork-server brute) then
  include it in the payload unchanged.
- **PIE/ASLR:** leak any code/libc pointer to de-randomize before jumping.
- Stack alignment: add a bare `ret` gadget before `system` (movaps).

## Finish
Get a shell on the remote, `cat flag`, grep the flag format. Save the working
pwntools script — the skeleton transfers to the next challenge.
