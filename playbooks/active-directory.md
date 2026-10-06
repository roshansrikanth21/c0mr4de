# Playbook: Active Directory Attacks

Internal/Windows engagements. Goal: low-priv foothold -> Domain Admin by abusing
Kerberos/LDAP/SMB trust. Mostly executed via the Kali container / operator tools,
not the web layer.

## Recon / foothold
No-cred enum: `enum4linux-ng`, `ldapsearch`, SMB null sessions, `nmap --script smb-*`.
LLMNR/NBT-NS poisoning with Responder -> NetNTLMv2 hashes.

## Map the domain
BloodHound (SharpHound collection) -> shortest path to DA via group membership,
sessions, ACLs. Single most useful step; everything else follows the graph.

## Get credentials
- Kerberoasting: request TGS for SPN accounts, crack offline (weak service pwds).
- AS-REP roasting: users without Kerberos pre-auth -> crackable hash, no creds.
- Password spraying: one password, many users (watch lockout thresholds).

## Lateral movement
pass-the-hash / pass-the-ticket via impacket (`psexec.py`/`wmiexec.py`/
`secretsdump.py`), `evil-winrm`, `NetExec`/`CrackMapExec` to spray across hosts.

## Escalate / persist
ACL/delegation abuse (BloodHound), DCSync (replicate krbtgt + hashes), Golden/Silver
tickets, unconstrained/constrained delegation.

## Report
PoC = authenticated access to a resource/host the account shouldn't reach, or a
cracked credential. Severity scales to Critical at DA. Tools: BloodHound, impacket,
NetExec, Responder, Rubeus, mimikatz, evil-winrm.

## Remediation
Strong service-account passwords + gMSA, disable LLMNR/NBT-NS, tiered admin, LAPS,
monitor Kerberoast/DCSync, least-privilege ACLs.
