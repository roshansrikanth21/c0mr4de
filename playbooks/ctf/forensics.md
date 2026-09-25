# CTF: Forensics

You're given a file (image, pcap, memory dump, disk image, office doc, audio) and
the flag is hidden in or recoverable from it. Discipline: exhaust the cheap
automated checks before manual analysis.

## Always run first (any file)
1. `file <x>` — real type ignores the extension.
2. `strings -n 6 <x> | grep -i flag` (and grep the challenge flag format).
3. `binwalk -e <x>` — carves embedded/appended files (a PNG with a zip glued on
   the end is the #1 CTF trick). `foremost` as a second carver.
4. `xxd | head` — inspect magic bytes; a wrong/patched header is common (fix it
   to open the file). `exiftool` for metadata (flags hide in Comment/Artist).

## Images / stego
- Appended data after the image's real EOF (binwalk catches this).
- `zsteg` (PNG/BMP LSB), `steghide extract` (JPG/WAV/BMP, often a passworded blob
  — password is usually in the prompt or another artifact), `stegsolve` for plane
  analysis / XOR / channel views.
- Corrupt PNG: fix the CRC / IHDR dimensions to reveal cropped-off content.
- QR/barcode fragments, text in the alpha channel.

## Audio
- Spectrogram (Audacity / Sonic Visualiser) — text drawn in the spectrum is
  classic. DTMF tones -> decode digits. Slow/reverse the track. LSB in WAV.

## PCAP / network
- Wireshark: `File > Export Objects` (HTTP/SMB/TFTP) to pull transferred files;
  Follow TCP/HTTP Stream. `tshark`/`strings` for quick greps.
- Look for creds in cleartext, base64 in headers, DNS-tunnel exfil (long
  subdomains), USB HID captures (decode keystrokes), unusual ports.
- Decrypt TLS if a keylog/`SSLKEYLOGFILE` or server key is provided.

## Memory (Volatility 3)
- `windows.info` / `pslist` / `pstree` / `cmdline` / `netscan`, `filescan` +
  `dumpfiles`, `windows.hashdump`, `clipboard`, `consoles`. The flag is often in a
  process's memory, a dumped file, or a command line.

## Disk / office
- `mmls` + `fls`/`icat` (Sleuth Kit) to recover deleted files; check slack space.
- Office/PDF: unzip docx/xlsx (they're zips), grep XML; `oletools`/`pdf-parser`
  for macros and embedded objects.

Grep the flag format after every extraction/decode.
