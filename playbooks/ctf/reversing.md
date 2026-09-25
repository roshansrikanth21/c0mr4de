# CTF: Reverse Engineering

You're given a binary (ELF/PE/APK/.pyc/wasm/etc.) that checks a flag or hides one.
Goal: recover the flag or the input that satisfies the check.

## Triage
1. `file` + `strings` — the flag or a hint is sometimes just sitting in strings.
2. Detect language/packer: Go/Rust/C/.NET/Python-frozen each need different tools;
   `detect-it-easy`/`strings` reveal UPX and other packers -> `upx -d` first.
3. Run it (in a VM/container) to see expected input/output behavior.

## Static
- **Ghidra** (free, primary) or IDA/Binary Ninja: decompile `main`, find the
  comparison against your input. Rename variables as you understand them.
- Follow the check: direct `strcmp` (flag is right there), a transform then
  compare (reverse the transform), or byte-by-byte math (recover each char).
- **.NET** -> dnSpy/ILSpy (near-source). **Java/APK** -> jadx. **Python .pyc** ->
  decompyle3/uncompyle6 (`pyinstxtractor` first for frozen exes). **wasm** ->
  wasm2wat.

## Dynamic
- **GDB + pwndbg / gef** (Linux), x64dbg (Windows): breakpoint the comparison,
  read the expected value from a register/memory at runtime — often trivially
  faster than reversing the math.
- `ltrace`/`strace` to catch `strcmp`/`memcmp`/syscalls with the flag as an arg.
- Patch the binary to bypass a check (flip a `jz`->`jnz`) when you only need it to
  print the flag.

## When the constraint is complex -> symbolic execution
- **angr**: model the input as symbolic, constrain "reach the win block / avoid
  the fail block," let the solver produce the input. The standard move for
  multi-constraint keygen-style challenges. `Z3` directly when you can read the
  constraints out of the decompiler.

## Keygens
Understand the validation algorithm, then implement the inverse to generate a
valid key. Grep output for the flag format.
