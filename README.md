<div align="center">

# 🩺 SfcRepairDoctor

**Fixes `sfc /scannow` → *"Windows Resource Protection found corrupt files but was unable to fix some of them"*. Runs live, shows progress the whole time, and needs no reboot.**

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white)
![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![No reboot](https://img.shields.io/badge/reboot-not%20required-success)
![Idempotent](https://img.shields.io/badge/re--run-safe-brightgreen)

</div>

---

## ✨ What it does

| | |
|---|---|
| 🔍 **Diagnoses** | Counts catalogs, checks signatures on System32 DLLs, and reads CBS.log for real findings |
| 🧩 **Restores catalogs** | Copies back missing package `.cat` files and OEM driver `oemN.cat` files from local Windows sources |
| 🔐 **Rebuilds trust** | CryptSvc indexes the restored catalogs live, and the DB is force-rebuilt only if needed |
| 🛠️ **Repairs the store** | `DISM /Online /Cleanup-Image /RestoreHealth` with a live percentage |
| ✅ **Verifies** | Runs `sfc /scannow` in a loop, parsing CBS.log for that run only, until it is clean |
| 📜 **Logs everything** | Timestamped log for each run in `logs\` |

Exit code **0** means only one thing: the final `sfc /scannow` reported **no integrity violations**.

---

## 🚀 Quick start

```powershell
git clone https://github.com/Michaelunkai/SfcRepairDoctor.git
cd SfcRepairDoctor
.\Run-SfcRepairDoctor.cmd          # double-click works too; it requests admin itself
```

| Option | Effect |
|---|---|
| `-DiagnoseOnly` | Only check and report, change nothing |
| `-SkipDism` | Skip DISM (about 3 min instead of about 17) |
| `-MaxSfcPasses N` | Max SFC verify passes (default 3) |

```powershell
.\Run-SfcRepairDoctor.cmd -DiagnoseOnly
```

---

## 🧠 The root cause it targets

SFC's PnP phase checks driver files against their **catalog signatures**. If the catalog store

```
C:\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}
```

gets emptied (by an aggressive cleanup or debloat tool, for example), every catalog-signed file
*looks* unsigned. SFC then logs hundreds of entries like these:

```
DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\acpi.sys
DEPLOY [Pnp] Failed repairing file: C:\WINDOWS\System32\drivers\acpi.sys: 160
```

The driver files themselves are fine (byte-identical to the DriverStore). SFC and DISM can't
rebuild catroot on their own, so running `sfc /scannow` again never helps. **SfcRepairDoctor
restores those catalogs from copies Windows already keeps** in `C:\Windows\servicing\Packages`
and the DriverStore. It downloads nothing.

---

## 🔄 Pipeline

```mermaid
flowchart LR
    A[1 Diagnose] --> B[2 Backup]
    B --> C[3 Restore catalogs]
    C --> D[4 Rebuild catalog DB]
    D --> E[5 DISM RestoreHealth]
    E --> F[6 SFC verify loop]
    F -->|still dirty| D
    F -->|clean| G((✅ exit 0))
```

Every phase is **idempotent**. On a healthy system it restores nothing and only verifies.
Nothing is deleted: `catroot2` is renamed (`catroot2.bak-<stamp>`), never removed.

---

## 📊 Proven result

Tested on Windows 11 Pro 25H2, build 26200.9457:

| | Before | After |
|---|---|---|
| catroot catalogs | 1 | **5,073** |
| Untrusted System32 DLLs (sample of 300) | 208 | **0** |
| SFC `[Pnp] Corrupt file` entries | ~150 per scan | **0** |
| `sfc /scannow` | ❌ *unable to fix some of them* | ✅ ***did not find any integrity violations*** |
| Reboot needed | | **No** |

The clean SFC result held on 3 independent full runs.

---

## ⚠️ Known DISM leftover (doesn't affect SFC)

`DISM /RestoreHealth` can still end with `0x800f0915` when CBS lists a **superseded**
package (state 80) whose files were already removed. Windows Update can't supply a superseded
package, so DISM reports it every time. If this happens, the tool names the package and its
state. It doesn't affect SFC or the running system.

The recurring `CSI Payload Corrupt (w) (Fixed) …\r\…` lines in CBS.log are only warnings
about removed reverse-delta files. They don't block anything.

---

## 📁 Files

```
SfcRepairDoctor/
├── Run-SfcRepairDoctor.cmd   # launcher (self-elevating)
├── SfcRepairDoctor.ps1       # the tool
├── logs/                     # per-run logs (git-ignored)
└── backups/                  # catroot snapshots per run (git-ignored)
```

<div align="center">

Made for anyone stuck in the endless `sfc /scannow` loop. 🛡️

</div>
