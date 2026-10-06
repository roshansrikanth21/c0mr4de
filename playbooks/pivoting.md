# Playbook: Pivoting and Tunnelling

After a foothold, reach networks not directly routable (internal ranges, segmented
VLANs). Plumbing for lateral movement.

## Forward types
- Local forward: `ssh -L 9000:10.0.0.5:3306 user@pivot` (reach internal service).
- Remote forward: `ssh -R 9001:localhost:4444 user@pivot` (callback through firewall).
- Dynamic SOCKS: `ssh -D 1080 user@pivot` then `proxychains <tool>`.

## Tools
SSH (`-L`/`-R`/`-D`) with creds; chisel (tunnel over HTTP, no SSH); ligolo-ng
(tun interface, no proxychains - preferred); proxychains-ng; Metasploit
`autoroute` + `socks_proxy`.

## Workflow
1. Enumerate the pivot's other interfaces (`ip a`, `route`) and what internal
   hosts/ports it can see.
2. Stand up a SOCKS proxy (chisel/ligolo/SSH -D).
3. Scan internal range through it: `proxychains nmap -sT -Pn 10.0.0.0/24` (full-connect
   only - SYN scans don't tunnel).
4. Attack internal services as if local; repeat per new host (multi-hop).

## Notes
Document tunnels; they're noisy and easy to lose track of. Keep scope in mind -
internal hosts reached via a pivot must still be in scope.
