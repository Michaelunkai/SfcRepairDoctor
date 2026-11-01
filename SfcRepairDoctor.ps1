<#
.SYNOPSIS
  SfcRepairDoctor - fixes "Windows Resource Protection found corrupt files but was
  unable to fix some of them" without rebooting, with live progress.

.DESCRIPTION
  Root cause found on this machine (2026-11-01): the catalog store
  C:\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE} had been emptied.
  With the .cat files gone, every catalog-signed system file looks unsigned, so the
  SFC PnP driver phase flags ~150 inbox drivers as "Corrupt file" and fails to repair
  them with error 160. DISM/SFC cannot restore catroot by themselves.

  Pipeline (each phase prints live progress, everything is logged under .\logs):
    1. Diagnose     - count catalogs, sample catalog signature health
    2. Backup       - snapshot catroot listing + catroot2 DB (reversible)
    3. Catalogs     - restore missing package catalogs from C:\Windows\servicing\Packages
                      and OEM driver catalogs (oemN.cat) from the DriverStore
    4. CatDB        - rebuild the CryptSvc catalog database (catroot2) live, no reboot
    5. DISM         - /Online /Cleanup-Image /RestoreHealth (component store)
    6. SFC loop     - sfc /scannow, parse CBS.log for this run, repeat until clean
  Exit code 0 only when the final sfc reports no integrity violations.

.PARAMETER MaxSfcPasses   Max sfc passes in the verify loop (default 3).
.PARAMETER SkipDism       Skip the DISM RestoreHealth phase.
.PARAMETER DiagnoseOnly   Only run phase 1 and the CBS analysis of the last sfc run.
#>
[CmdletBinding()]
param(
    [int]$MaxSfcPasses = 3,
    [switch]$SkipDism,
    [switch]$DiagnoseOnly
)

$ErrorActionPreference = 'Stop'
$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir    = Join-Path $Root 'logs'
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog    = Join-Path $LogDir "run-$Stamp.log"
$Sys32     = Join-Path $env:windir 'System32'
$CatRoot   = Join-Path $Sys32 'catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$CatRoot2  = Join-Path $Sys32 'catroot2'
$PkgDir    = Join-Path $env:windir 'servicing\Packages'
$DrvStore  = Join-Path $Sys32 'DriverStore\FileRepository'
$InfDir    = Join-Path $env:windir 'INF'
$CbsLog    = Join-Path $env:windir 'Logs\CBS\CBS.log'

# ---------- elevation ----------
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Not elevated - relaunching as Administrator...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',"`"$($MyInvocation.MyCommand.Path)`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v) { $a += "-$k" } } else { $a += "-$k"; $a += "$v" }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    exit
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Log([string]$msg, [string]$color = 'Gray') {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $RunLog -Value $line -Encoding UTF8
}
function Phase([int]$n, [string]$title) {
    Log ''
    Log ("===== PHASE {0}: {1} =====" -f $n, $title) 'Cyan'
}

# ---------- helpers ----------
function Get-CatalogCount { @(Get-ChildItem -LiteralPath $CatRoot -Filter *.cat -ErrorAction SilentlyContinue).Count }

function Get-SignatureHealth([int]$sample = 300) {
    $files = Get-ChildItem (Join-Path $Sys32 '*.dll') | Select-Object -First $sample
    $bad = 0
    foreach ($f in $files) { if ((Get-AuthenticodeSignature $f.FullName).Status -ne 'Valid') { $bad++ } }
    [pscustomobject]@{ Sample = $files.Count; Unsigned = $bad }
}

# Read a file another process still has open for writing.
function Read-Shared([string]$path, [Text.Encoding]$enc) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $ms = New-Object IO.MemoryStream
        $fs.CopyTo($ms)
        $enc.GetString($ms.ToArray())
    } finally { $fs.Close() }
}

# Tail a redirected stdout file while a process runs; report the latest NN% seen.
function Invoke-WithProgress([string]$exe, [string]$argList, [string]$activity, [Text.Encoding]$enc) {
    $out = Join-Path $LogDir ("{0}-{1}-{2}.out" -f $activity, $Stamp, (Get-Random))
    $p = Start-Process -FilePath $exe -ArgumentList $argList -NoNewWindow -PassThru `
         -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    $null = $p.Handle   # cache the handle so ExitCode survives process exit
    $last = -1; $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 700
        $pct = $null
        try {
            $text  = Read-Shared $out $enc
            $m = [regex]::Matches($text, '(\d{1,3}(?:\.\d)?)\s*%')
            if ($m.Count) { $pct = [double]$m[$m.Count-1].Groups[1].Value }
        } catch {}
        if ($pct -ne $null -and [int]$pct -ne $last) {
            $last = [int]$pct
            Write-Progress -Activity $activity -Status ("{0}% - {1:mm\:ss} elapsed" -f $last, $sw.Elapsed) -PercentComplete ([math]::Min(100,$last))
            Log ("  {0}: {1}% ({2:mm\:ss})" -f $activity, $last, $sw.Elapsed)
        }
    }
    $p.WaitForExit()
    Write-Progress -Activity $activity -Completed
    $text = Read-Shared $out $enc
    $clean = ($text -replace "`0", '') -split "`r?`n|`r" | Where-Object { $_.Trim() } | Select-Object -Last 8
    foreach ($l in $clean) { Log "  > $($l.Trim())" }
    [pscustomobject]@{ ExitCode = $p.ExitCode; Text = ($text -replace "`0", '') }
}

# CBS.log lines written since $since: PnP "Corrupt file" + SR "Cannot repair".
function Get-CbsFindings([datetime]$since) {
    $res = [pscustomobject]@{ PnpCorrupt = @(); SrCannot = @(); SrRepaired = @() }
    if (-not (Test-Path $CbsLog)) { return $res }
    $fs = [IO.File]::Open($CbsLog, 'Open', 'Read', 'ReadWrite')
    $sr = New-Object IO.StreamReader($fs)
    try {
        while (($line = $sr.ReadLine()) -ne $null) {
            if ($line.Length -lt 20) { continue }
            $ts = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($line.Substring(0,19), 'yyyy-MM-dd HH:mm:ss', $null, 0, [ref]$ts)) { continue }
            if ($ts -lt $since) { continue }
            if ($line -match '\[Pnp\] Corrupt file: (.+)$')     { $res.PnpCorrupt += $Matches[1].Trim() }
            elseif ($line -match '\[SR\] Cannot repair member file (.+)$') { $res.SrCannot += $Matches[1].Trim() }
            elseif ($line -match '\[SR\] Repairing file (.+) from store') { $res.SrRepaired += $Matches[1].Trim() }
        }
    } finally { $sr.Close() }
    $res
}

function Restart-CryptSvcRebuild {
    $ErrorActionPreference = 'Continue'
    Log '  stopping CryptSvc (retrying while busy)...'
    $stopped = $false
    for ($t = 1; $t -le 10 -and -not $stopped; $t++) {
        try { Stop-Service -Name CryptSvc -Force -ErrorAction Stop } catch { Log "    attempt ${t}: $($_.Exception.Message)" 'DarkYellow' }
        Start-Sleep -Seconds 2
        $stopped = (Get-Service CryptSvc).Status -eq 'Stopped'
    }
    if ($stopped) {
        $bak = "$CatRoot2.bak-$Stamp"
        try {
            Rename-Item -LiteralPath $CatRoot2 -NewName (Split-Path $bak -Leaf) -ErrorAction Stop
            Log "  catroot2 moved to $bak (rebuilt fresh)" 'Green'
        } catch {
            Log "  could not move catroot2 ($($_.Exception.Message)); resyncing in place" 'Yellow'
        }
    } else {
        Log '  CryptSvc busy - resyncing catalog DB in place (it indexes new catroot files live)' 'Yellow'
    }
    for ($t = 1; $t -le 10 -and (Get-Service CryptSvc).Status -ne 'Running'; $t++) {
        try { Start-Service -Name CryptSvc -ErrorAction Stop } catch { Start-Sleep -Seconds 2 }
    }
    Log "  CryptSvc status: $((Get-Service CryptSvc).Status)"
    # Force the catalog DB to (re)index everything by touching the trust APIs.
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Log '  waiting for catalog DB to index (signature probe until stable)...'
    $prev = -1
    for ($i = 0; $i -lt 60; $i++) {
        $h = Get-SignatureHealth 120
        $pct = [int](100 * ($h.Sample - $h.Unsigned) / [math]::Max(1,$h.Sample))
        Write-Progress -Activity 'Catalog DB rebuild' -Status "$pct% of probe files trusted" -PercentComplete $pct
        Log ("    probe {0}: {1}/{2} unsigned ({3:mm\:ss})" -f ($i+1), $h.Unsigned, $h.Sample, $sw.Elapsed)
        if ($h.Unsigned -eq $prev -and $i -ge 1) { break }
        $prev = $h.Unsigned
        Start-Sleep -Seconds 5
    }
    Write-Progress -Activity 'Catalog DB rebuild' -Completed
}

# ======================================================================
Log "SfcRepairDoctor run $Stamp  (log: $RunLog)" 'White'
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Log ("OS: {0} {1} build {2}.{3}" -f $os.ProductName, $os.DisplayVersion, $os.CurrentBuild, $os.UBR)

Phase 1 'Diagnose'
$catBefore = Get-CatalogCount
$pkgCats   = @(Get-ChildItem -LiteralPath $PkgDir -Filter *.cat)
$health    = Get-SignatureHealth
Log "  catroot catalogs present : $catBefore"
Log "  package catalogs on disk : $($pkgCats.Count)"
Log ("  signature probe          : {0}/{1} System32 DLLs NOT trusted" -f $health.Unsigned, $health.Sample) ($(if ($health.Unsigned) {'Yellow'} else {'Green'}))
$lastSfc = Get-CbsFindings ((Get-Date).AddHours(-12))
Log "  CBS (last 12h): PnP corrupt=$($lastSfc.PnpCorrupt.Count)  SR cannot-repair=$($lastSfc.SrCannot.Count)  SR repaired=$($lastSfc.SrRepaired.Count)"
if ($DiagnoseOnly) { Log 'DiagnoseOnly - stopping.' 'Cyan'; exit 0 }

Phase 2 'Backup (reversible)'
$bakDir = Join-Path $Root "backups\$Stamp"
New-Item -ItemType Directory -Force -Path $bakDir | Out-Null
Get-ChildItem -LiteralPath $CatRoot | Select-Object Name, Length, LastWriteTime |
    Export-Csv (Join-Path $bakDir 'catroot-before.csv') -NoTypeInformation
Copy-Item -LiteralPath (Join-Path $CatRoot2 'dberr.txt') $bakDir -ErrorAction SilentlyContinue
Log "  catroot listing + dberr.txt saved to $bakDir (catroot2 itself is renamed, not deleted, in phase 4)"

Phase 3 'Restore missing catalogs'
$present = @{}
Get-ChildItem -LiteralPath $CatRoot -Filter *.cat | ForEach-Object { $present[$_.Name.ToLower()] = $true }
$added = 0; $i = 0
foreach ($c in $pkgCats) {
    $i++
    if ($i % 100 -eq 0 -or $i -eq $pkgCats.Count) {
        $pct = [int](100 * $i / $pkgCats.Count)
        Write-Progress -Activity 'Restoring package catalogs' -Status "$i / $($pkgCats.Count)  (added $added)" -PercentComplete $pct
        if ($i % 500 -eq 0 -or $i -eq $pkgCats.Count) { Log "  package catalogs: $i/$($pkgCats.Count) checked, $added restored" }
    }
    if ($present.ContainsKey($c.Name.ToLower())) { continue }
    Copy-Item -LiteralPath $c.FullName -Destination (Join-Path $CatRoot $c.Name)
    $added++
}
Write-Progress -Activity 'Restoring package catalogs' -Completed
Log "  package catalogs restored: $added" 'Green'

# OEM driver catalogs: catroot\oemN.cat <- DriverStore\<orig>.inf_*\<CatalogFile>
$oemAdded = 0
$oemInfs = @(Get-ChildItem -LiteralPath $InfDir -Filter 'oem*.inf')
foreach ($inf in $oemInfs) {
    $target = Join-Path $CatRoot ($inf.BaseName + '.cat')
    if (Test-Path -LiteralPath $target) { continue }
    $catName = $null
    foreach ($l in (Get-Content -LiteralPath $inf.FullName -ErrorAction SilentlyContinue)) {
        if ($l -match '^\s*CatalogFile(\.NT(amd64)?)?\s*=\s*([^\s;]+)') { $catName = $Matches[3]; if ($Matches[2]) { break } }
    }
    if (-not $catName) { continue }
    # expand %Token% from the INF [Strings] section (e.g. Npcap: %NPF_DriverName%.cat)
    $catName = [regex]::Replace($catName, '%([^%]+)%', {
        param($m)
        $k = [regex]::Escape($m.Groups[1].Value)
        $hit = Select-String -LiteralPath $inf.FullName -Pattern "^\s*$k\s*=\s*`"?([^`";]+)" | Select-Object -First 1
        if ($hit) { $hit.Matches[0].Groups[1].Value.Trim() } else { $m.Value }
    })
    $infHash = (Get-FileHash -LiteralPath $inf.FullName -Algorithm SHA256).Hash
    $src = $null
    foreach ($d in (Get-ChildItem -LiteralPath $DrvStore -Directory)) {
        $cand = Get-ChildItem -LiteralPath $d.FullName -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cand) { continue }
        if ($cand.Length -ne $inf.Length) { continue }
        if ((Get-FileHash -LiteralPath $cand.FullName -Algorithm SHA256).Hash -ne $infHash) { continue }
        $p = Join-Path $d.FullName $catName
        if (Test-Path -LiteralPath $p) { $src = $p; break }
    }
    if ($src) { Copy-Item -LiteralPath $src -Destination $target; $oemAdded++ }
    else { Log "  no DriverStore catalog for $($inf.Name) ($catName)" 'DarkYellow' }
}
Log "  OEM driver catalogs restored: $oemAdded of $($oemInfs.Count) oem*.inf" 'Green'
Log "  catroot catalogs now: $(Get-CatalogCount) (was $catBefore)"

Phase 4 'Rebuild catalog database (CryptSvc, live)'
$health2 = Get-SignatureHealth
if ($health2.Unsigned) {
    Log "  $($health2.Unsigned) probe files still untrusted - rebuilding catalog DB" 'Yellow'
    Restart-CryptSvcRebuild
    $health2 = Get-SignatureHealth
} else { Log '  catalog DB already trusts every probe file - no rebuild needed' 'Green' }
Log ("  signature probe after rebuild: {0}/{1} NOT trusted (was {2})" -f $health2.Unsigned, $health2.Sample, $health.Unsigned) ($(if ($health2.Unsigned) {'Yellow'} else {'Green'}))

if (-not $SkipDism) {
    Phase 5 'DISM RestoreHealth'
    $d = Invoke-WithProgress 'dism.exe' '/Online /Cleanup-Image /RestoreHealth' 'DISM' ([Text.Encoding]::Default)
    Log "  DISM exit code: $($d.ExitCode)" ($(if ($d.ExitCode -eq 0) {'Green'} else {'Red'}))
    if ($d.ExitCode -ne 0) {
        # Name the packages DISM could not source, and flag superseded orphans (harmless to SFC).
        $cbsPkgs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        $missing = Select-String -LiteralPath $CbsLog -Pattern 'Could not find missing package manifest/cat for package:(\S+)' |
                   ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
        foreach ($m in $missing) {
            $state = (Get-ItemProperty -LiteralPath (Join-Path $cbsPkgs $m) -ErrorAction SilentlyContinue).CurrentState
            $kind  = switch ($state) { 80 {'SUPERSEDED orphan - files already scavenged, does not affect SFC'} 112 {'INSTALLED - needs a repair source (/Source:<ISO>\sources\install.wim)'} default {"state=$state"} }
            Log "  DISM missing source: $m  [$kind]" 'Yellow'
        }
    }
}

Phase 6 'SFC verify loop'
$clean = $false
for ($pass = 1; $pass -le $MaxSfcPasses; $pass++) {
    Log "  --- sfc pass $pass/$MaxSfcPasses ---" 'White'
    $since = (Get-Date).AddSeconds(-2)
    $s = Invoke-WithProgress 'sfc.exe' '/scannow' "SFC-pass$pass" ([Text.Encoding]::Unicode)
    $f = Get-CbsFindings $since
    Log "  CBS this pass: PnP corrupt=$($f.PnpCorrupt.Count)  SR cannot-repair=$($f.SrCannot.Count)  SR repaired=$($f.SrRepaired.Count)"
    $f.PnpCorrupt | Select-Object -First 10 | ForEach-Object { Log "    pnp: $_" 'DarkYellow' }
    $f.SrCannot   | Select-Object -First 10 | ForEach-Object { Log "    sr : $_" 'DarkYellow' }
    if ($s.Text -match 'did not find any integrity violations') {
        Log '  RESULT: Windows Resource Protection did not find any integrity violations.' 'Green'
        $clean = $true; break
    } elseif ($s.Text -match 'successfully repaired') {
        Log '  RESULT: repaired this pass - re-verifying...' 'Yellow'
    } else {
        Log '  RESULT: still unable to fix some files.' 'Red'
        if ($f.PnpCorrupt.Count -and $pass -lt $MaxSfcPasses) {
            Log '  PnP driver files still flagged - rebuilding catalog DB again before next pass' 'Yellow'
            Restart-CryptSvcRebuild
        }
    }
}

Log ''
if ($clean) {
    Log 'SUCCESS: sfc /scannow is clean. No reboot was needed.' 'Green'
    exit 0
} else {
    Log "NOT CLEAN after $MaxSfcPasses passes - see $RunLog and $CbsLog" 'Red'
    exit 1
}
