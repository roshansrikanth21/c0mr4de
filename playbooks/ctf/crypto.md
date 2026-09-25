# CTF: Crypto

CTF crypto is almost never "break AES" — it's spotting a *misuse* of otherwise
sound primitives. Identify the scheme first, then match to its known weakness.

## Identify
- Look at the ciphertext shape: length a multiple of 16 (AES block), huge integers
  (RSA), hex/base64 layers, a public key file (`openssl` to read params).
- Read the challenge source (usually provided) — the bug is in *how* they used the
  primitive, and the source shows it.

## Classical (low point)
- Caesar/ROT/Vigenère/substitution -> frequency analysis, `rot13`, dcode-style.
- XOR: single-byte (brute all 256, crib-drag for the flag prefix), repeating-key
  (find keylen via Hamming distance, then per-column single-byte XOR = "break
  repeating-key XOR").
- Base families: base64/32/16/85/58, Morse, binary, hex — often stacked; peel
  layer by layer. `--` in output often means another encoding pass.

## RSA (the CTF workhorse — check these in order)
- **Small e (e=3)** + no padding -> cube-root the ciphertext if `m^e < n`.
- **N factorable:** paste N into factordb; if it's there, you win. Small N ->
  factor locally. Close primes -> Fermat factorization.
- **Common modulus** (same N, two e) -> extended Euclid combine.
- **Håstad broadcast** (same m, e recipients, different N) -> CRT + e-th root.
- **Wiener** (large e / small d) -> continued-fraction attack.
- **Partial key leak** -> Coppersmith (sage). Reuse of p across two moduli ->
  `gcd(N1,N2)` recovers p instantly.
- Tooling: `RsaCtfTool` throws every known attack at a public key — try it early.

## Symmetric / modern misuse
- **AES-ECB:** identical plaintext blocks -> identical ciphertext. ECB
  byte-at-a-time decryption when you control a prefix ("ECB cut-and-paste").
- **AES-CBC:** padding oracle (a server that reveals pad validity) -> full
  decrypt/encrypt without the key. Bit-flipping in the IV/prior block to tamper
  plaintext. **Fixed/predictable IV** was the actual Haveloc bug — always check it.
- **CTR/stream nonce reuse** -> XOR two ciphertexts, cancels the keystream.
- **AES-GCM nonce reuse** -> forge tags (Joux / GHASH recovery).
- **Hash length extension** (MAC = H(secret‖msg)) -> hashpump / `hlextend`.

## After decrypting
Grep for the flag format. If the plaintext looks like more encoding, keep peeling.
