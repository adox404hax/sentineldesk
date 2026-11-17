# Windows JSON-lines format

One JSON object per line:

```json
{"TimeCreated":"2026-11-17T10:00:00Z","EventID":4625,"Computer":"RDS01",
 "EventData":{"TargetUserName":"alice","IpAddress":"198.51.100.77","LogonType":"10"}}
```

| EventID | Meaning | `EventData` fields read |
|---|---|---|
| 4624 / 4625 | Logon success / failure | TargetUserName, IpAddress, LogonType |
| 4688 or Sysmon 1 | Process created | SubjectUserName (or User), NewProcessName (or Image), CommandLine, ParentProcessName (or ParentImage) |
| 4720 | User account created | SubjectUserName (actor), TargetUserName (new account) |
| 4728 / 4732 / 4756 | Member added to group | SubjectUserName, TargetUserName (group), MemberName |
| 7045 | Service installed | ServiceName, ImagePath, SubjectUserName (optional) |
| 1102 | Audit log cleared | SubjectUserName |

Enable command-line auditing for 4688 (`Include command line in process creation events`) or collect Sysmon.
Other event IDs are ignored.
