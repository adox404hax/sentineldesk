# Playbook: credential attack (brute force, spray, success after failures)

**Triggers**: `login-bruteforce`, `password-spray`, `bruteforce-success`

1. **Scope**: list the source IP(s), targeted accounts, targeted hosts and the time window from the incident.
2. **Did it work?** A `bruteforce-success` alert means yes. Otherwise search for any 4624 / `Accepted` from the same IP.
3. **Contain**: block the IP at the edge; if an account succeeded, disable it and revoke sessions and tokens.
4. **Look after the login**: everything that account or IP did next (process creation, new accounts, services,
   log clearing). If anything appears, switch to the [post-compromise playbook](post-compromise.md).
5. **Enrich**: check the IP against threat intel (AbuseIPDB, OTX, VirusTotal) and whether other accounts or hosts saw it.
6. **Recover**: reset the password, enforce MFA, review lockout policy and exposure (why was RDP or SSH reachable?).
7. **Document**: timeline, IOCs (IP, usernames), verdict (true positive), root cause, preventive control added.

**Escalate** when a privileged or service account succeeded, or when the source IP appears in other incidents.
