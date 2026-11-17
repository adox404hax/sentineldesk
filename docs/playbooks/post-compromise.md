# Playbook: post-compromise activity on a host

**Triggers**: `encoded-powershell`, `certutil-download`, `lolbin-remote-exec`, `new-local-user`, `admin-group-add`,
`suspicious-service`, `log-cleared`

1. **Treat as hands-on-keyboard**: more than two of these on one host, or any `log-cleared`, means escalate to incident
   response now.
2. **Isolate** the host from the network (EDR isolation, VLAN quarantine) but keep it powered on to preserve memory.
3. **Preserve**: collect forwarded SIEM copies of logs from before any clear, plus a memory image and the dropped files.
4. **Decode and extract IOCs**: Base64 PowerShell (UTF-16LE), URLs fetched by certutil or mshta, hashes of dropped files,
   service names and paths.
5. **Hunt**: search the estate for the same IOCs, the same new account name, and the same service name.
6. **Eradicate**: remove the rogue account, group membership, service and binaries; rotate credentials the host could reach.
7. **Recover and review**: rebuild from a known-good image if integrity is in doubt; document the timeline and gaps
   (for example, why the first alert did not stop the attacker).
