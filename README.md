# pipeacl

Fast Windows named pipe ACL enumeration tool. Lists all running pipes with their writable DACLs in ~2 seconds.

## Usage

```
pipeacl [-v] [-j] [-f writable]
```

| Flag | Description |
|------|-------------|
| `-v` | Verbose - include SDDL string |
| `-j` | JSON output |
| `-f writable` | Show only writable pipes (impersonation candidates) |

## Output Examples

**Default:**
```
\\.\pipe\svcpipe   BUILTIN\Users:RW
\\.\pipe\epmapper  NT AUTHORITY\SYSTEM:F
```

**JSON (`-j`):**
```json
[{"pipe":"\\\\.\\pipe\\svcpipe","writable":true,"sid":"S-1-5-32-545"}]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Access denied |
| 2 | No pipes found |

## Build

```bash
# Native Windows
cargo build --release

# Cross-compile from Linux/macOS
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## Internals

- Uses `FindFirstFile`/`FindNextFile` on `\\.\pipe\*` to enumerate pipes
- `GetSecurityInfo` with `SE_KERNEL_OBJECT` to grab DACL
- `IsWellKnownSid` + ACCESS_MASK check for `GENERIC_WRITE | WRITE_DAC | WRITE_OWNER`
- SID→name lookup cached for speed
