# World's End Protect

A classroom-software guardian for Windows labs. It keeps teaching software
(e.g. MyClass/极域-style classroom clients) running on student PCs, stops
students from killing it or running cracked tools/viruses, and lets the teacher
configure and push the policy from one console over the network.

> Defense-side tool. It hardens the *student endpoint* against tampering; it is
> not an attack tool and does not bypass any other software.

## Architecture

Two independent executables, no third-party dependencies (pure .NET Framework 4.x).

```
 Teacher PC                                  Student PCs (N)
┌────────────────────┐   HTTP /policy   ┌────────────────────┐
│ TeacherConsole.exe │ ───────────────▶ │ StudentGuard.exe    │
│  (WinForms GUI)    │   HTTP /heartbeat │  (Windows service,   │
│  - edit policy     │ ◀─────────────── │   headless, 3-replica│
│  - start server    │                  │   mutual guard)     │
└────────────────────┘                  └────────────────────┘
```

- **TeacherConsole.exe** — runs on the teacher PC. You freely add the classroom
  software to guard, list banned processes/features, set the AppLocker whitelist
  and scan dirs, then start a small HTTP server. It shows which students are online.
- **StudentGuard.exe** — runs as a Windows service on every student PC. Every
  ~10 s it pulls the encrypted policy from the teacher console, keeps the classroom
  client alive, kills banned processes, and quarantines freshly downloaded
  executables. It protects itself: three replicas watch each other, its own
  binaries are hash-checked and restored from backup, and install paths are ACL-locked.

## Build

Requires only the .NET Framework csc (already on Windows). No Visual Studio.

```cmd
build.cmd
```

Outputs `bin\StudentGuard.exe` and `bin\TeacherConsole.exe`.

## Quick start

1. On the teacher PC: run `TeacherConsole.exe` (as Administrator).
   - **Guarded software**: process name (no `.exe`) + full launch path of the classroom client.
   - **Banned features**: process names to kill on sight (cracked clients, etc.).
   - **Defense**: AppLocker whitelist dirs + download/temp dirs to scan.
   - Set the port (default `8300`) and click **Start policy server**.
2. On each student PC: install `StudentGuard.exe` as a service, write the teacher
   console URL into `teacher.url` next to the exe (e.g. `http://192.168.1.10:8300`),
   and deploy the three-replica self-protection. Students then pull the policy
   automatically and appear in the console's **Online students** tab.

## Policy transport

The policy is the line-based text you edit; before being sent it is AES-256-CBC
encrypted and base64-encoded. The student endpoint decrypts it in memory and
hot-applies only the fields the teacher is allowed to change (targets, banned
processes, whitelist, scan dirs, poll interval). Self-protection (replica list,
integrity hashes, locked paths) is set at local install and is never overwritten
by the network — a compromised teacher console cannot rewrite the student's
self-defense.

## Notes & limits

- Hardened against *students* (standard-user, casual tampering). It is not
  driver-grade protection against an administrator on the machine.
- AES key/IV are compiled into the exe (reasonable for a classroom, not for
  against a determined reverse engineer).
- Works best when student accounts are standard users; see your classroom image.

## License

MIT, see [LICENSE](LICENSE).
