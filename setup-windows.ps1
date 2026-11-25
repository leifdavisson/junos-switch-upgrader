<#
SPDX-License-Identifier: AGPL-3.0-or-later

.SYNOPSIS
  Assess and fix a Windows machine so Junos-Switch-Upgrader can run.

.DESCRIPTION
  Checks (and with -Fix, repairs) common issues on first Windows runs:
    1. Python / Git missing, or installed but not on PATH
    2. Python version (>=3.10; prefers 3.12 for prebuilt wheels)
    3. Missing Microsoft Visual C++ Redistributable (x64 vs x86 matching Python arch)
    4. Virtual environment + editable install (click, netmiko, paramiko, pyyaml, rich)
    5. Local deliverables/firmware/manifests working directories
    6. Windows Defender slowdown (optional -Fix -DefenderExclusion) & inbound HTTP port (optional -Fix -FirewallRule)

  Default is ASSESS ONLY (changes nothing). Use -Fix to install/repair.
  Installs use winget: https://learn.microsoft.com/windows/package-manager/winget/
  Direct fallback downloads verify Authenticode signatures (and optional SHA-256 hashes) before execution.
  Read-only with respect to the network: this script never touches any target switch.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1          # assess only
  powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -Fix     # assess + fix
  powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -Fix -FirewallRule
#>
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$DefenderExclusion,  # optional, requires -Fix + admin: exclude project folder from real-time scan
    [switch]$FirewallRule,       # optional, requires -Fix + admin: allow inbound TCP for unified HTTP firmware server
    [ValidateRange(1, 65535)]
    [int]$HttpPort = 8080,
    [string]$FirewallRemoteAddress = 'LocalSubnet'
)

$ErrorActionPreference = 'Continue'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Problems = 0
$script:Fixed = 0
$script:NeedNewShell = $false
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

function Ok($m)   { Write-Host "[ OK ]  $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[FAIL]  $m" -ForegroundColor Red; $script:Problems++ }
function Info($m) { Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Fixd($m) { Write-Host "[FIXD]  $m" -ForegroundColor Yellow; $script:Fixed++ }

function Refresh-Path {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($m, $u) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $env:Path = ($parts -join ';')
}

function Add-ToUserPath($dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return $false }
    $normalizedTarget = $dir.TrimEnd('\')
    $regKey = $null
    try {
        $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        $rawUserPath = ''
        if ($null -ne $regKey) {
            $val = $regKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $val) { $rawUserPath = [string]$val }
        }
        $entries = @($rawUserPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $normalizedExisting = @($entries | ForEach-Object { $_.TrimEnd('\') })
        if ($normalizedExisting -notcontains $normalizedTarget) {
            $newValue = if ($entries.Count -gt 0) { ($entries -join ';') + ";$dir" } else { $dir }
            if ($null -ne $regKey) {
                $regKey.SetValue('Path', $newValue, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            } else {
                [Environment]::SetEnvironmentVariable('Path', $newValue, 'User')
            }
            if ([string]::IsNullOrWhiteSpace($env:Path)) {
                $env:Path = $dir
            } else {
                $env:Path = $env:Path.TrimEnd(';') + ";$dir"
            }
            $script:NeedNewShell = $true
            return $true
        }
        return $false
    } finally {
        if ($null -ne $regKey) { $regKey.Dispose() }
    }
}

$pyInstallScope = if ($script:IsAdmin) { 'InstallAllUsers=1' } else { 'InstallAllUsers=0' }
$Fallbacks = @{
    'Python.Python.3.12' = @{
        Url              = 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe'
        Args             = "/quiet $pyInstallScope PrependPath=1 Include_launcher=1 Include_test=0"
        PublisherPattern = 'Python Software Foundation'
        Sha256           = ''
    }
    'Git.Git' = @{
        Url              = 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe'
        Args             = '/VERYSILENT /NORESTART'
        PublisherPattern = '(Johannes Schindelin|Git Development Community|Git for Windows)'
        Sha256           = ''
    }
    'Microsoft.VCRedist.2015+.x64' = @{
        Url              = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
        Args             = '/install /quiet /norestart'
        PublisherPattern = 'Microsoft Corporation'
        Sha256           = ''
    }
    'Microsoft.VCRedist.2015+.x86' = @{
        Url              = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
        Args             = '/install /quiet /norestart'
        PublisherPattern = 'Microsoft Corporation'
        Sha256           = ''
    }
}

function Test-SignedInstaller {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$PublisherPattern,
        [string]$ExpectedSha256 = ''
    )
    if (-not (Test-Path -LiteralPath $FilePath) -or (Get-Item -LiteralPath $FilePath).Length -le 0) {
        Bad "Downloaded installer missing or empty: $FilePath"
        return $false
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $actualHash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -ne $ExpectedSha256.ToUpperInvariant()) {
            Bad "SHA-256 mismatch for $FilePath (got $actualHash, expected $ExpectedSha256)."
            return $false
        }
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) {
        Bad "Authenticode signature invalid for $FilePath (status=$($sig.Status)). Refusing to execute."
        return $false
    }
    if ($sig.SignerCertificate.Subject -notmatch $PublisherPattern) {
        Bad "Unexpected installer publisher for ${FilePath}: $($sig.SignerCertificate.Subject)"
        return $false
    }
    Ok "Verified signed installer ($($sig.SignerCertificate.Subject))"
    return $true
}

function Ensure-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
    Info "winget missing; trying to register/install App Installer..."
    try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop } catch {}
    Refresh-Path
    if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }

    $tmp = Join-Path $env:TEMP ("junos-winget-" + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Force -Path $tmp -ErrorAction Stop | Out-Null
        $vclibsPath = Join-Path $tmp 'vclibs.appx'
        $wingetPath = Join-Path $tmp 'winget.msixbundle'
        Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile $vclibsPath -UseBasicParsing -ErrorAction Stop
        Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $wingetPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-SignedInstaller -FilePath $vclibsPath -PublisherPattern 'Microsoft Corporation')) { return $false }
        if (-not (Test-SignedInstaller -FilePath $wingetPath -PublisherPattern 'Microsoft Corporation')) { return $false }
        Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue
        Add-AppxPackage -Path $wingetPath -ErrorAction Stop
    } catch {
        Info "winget bootstrap failed: $($_.Exception.Message)"
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    $env:Path = $env:Path.TrimEnd(';') + ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
    return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Winget-Install($id) {
    if (Ensure-Winget) {
        & winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements
        $wingetExit = $LASTEXITCODE
        Refresh-Path
        # 0 = installed, -1978335189 (0x8A15002B) / -1978335212 (0x8A150014) = already installed / no applicable update
        if ($wingetExit -in 0, -1978335189, -1978335212) { return $true }
        Info "winget install of $id failed (exit $wingetExit); trying verified direct download."
    }
    $fb = $Fallbacks[$id]
    if (-not $fb) { Bad "No installer available for $id."; return $false }
    $tmp = Join-Path $env:TEMP ("junos-setup-" + [Guid]::NewGuid().ToString('N'))
    $exe = Join-Path $tmp (Split-Path $fb.Url -Leaf)
    try {
        New-Item -ItemType Directory -Force -Path $tmp -ErrorAction Stop | Out-Null
        Info "Downloading $($fb.Url)"
        Invoke-WebRequest -Uri $fb.Url -OutFile $exe -UseBasicParsing -ErrorAction Stop
        if (-not (Test-SignedInstaller -FilePath $exe -PublisherPattern $fb.PublisherPattern -ExpectedSha256 $fb.Sha256)) {
            return $false
        }
        $p = Start-Process -FilePath $exe -ArgumentList $fb.Args -Wait -PassThru -ErrorAction Stop
        Refresh-Path
        return ($null -ne $p -and $p.ExitCode -in 0, 3010)
    } catch {
        Bad "Direct download/install failed: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-Prereqs {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSVersion.Major -lt 5) { Bad "PowerShell 5.1+ required (found $($PSVersionTable.PSVersion))." }
    if (-not [Environment]::Is64BitOperatingSystem) { Bad "32-bit Windows detected; current Python 3.12 installers target 64-bit." }
    if (-not [string]::IsNullOrWhiteSpace($env:HTTPS_PROXY) -or -not [string]::IsNullOrWhiteSpace($env:https_proxy)) {
        Info "HTTPS_PROXY detected; skipping direct TCP:443 reachability probes."
    } else {
        foreach ($h in 'pypi.org', 'files.pythonhosted.org', 'github.com') {
            if (-not (Test-NetConnection $h -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
                Bad "Cannot reach ${h}:443 (firewall/proxy?). Set HTTPS_PROXY or allow outbound HTTPS."
            } else { Ok "Reachable: $h" }
        }
    }
    $lp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction SilentlyContinue).LongPathsEnabled
    if ($lp -ne 1) {
        Info "Windows long paths are disabled (can break pip on deep paths)."
        if ($Fix) {
            try {
                Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' LongPathsEnabled 1 -ErrorAction Stop
                Fixd "Enabled long paths."
            } catch { Info "Run as Administrator to enable long paths." }
        }
    } else { Ok "Long paths enabled" }

    if ($Fix -and -not $script:IsAdmin) {
        Info "Not running as Administrator: machine-wide installs/firewall/Defender changes require an elevated PowerShell."
    }
}

Write-Host "`n=== Junos-Switch-Upgrader Windows Setup ($(if ($Fix) {'FIX'} else {'ASSESS ONLY'})) ===`n"

Test-Prereqs

# --- OS / architecture ---------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -ne $os) {
    Info "OS: $($os.Caption) build $($os.BuildNumber), arch: $($env:PROCESSOR_ARCHITECTURE)"
    if ([int]$os.BuildNumber -lt 17763) { Bad "Windows older than 10 1809 is unsupported by current Python." }
} else {
    Info "Unable to query Win32_OperatingSystem via CIM."
}

# --- Git -------------------------------------------------------------------
Refresh-Path
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    $gitDir = @("$env:ProgramFiles\Git\cmd", "${env:ProgramFiles(x86)}\Git\cmd", "$env:LOCALAPPDATA\Programs\Git\cmd") |
        Where-Object { Test-Path -LiteralPath "$_\git.exe" } | Select-Object -First 1
    if ($gitDir) {
        Bad "Git is installed at $gitDir but is not on PATH."
        if ($Fix -and (Add-ToUserPath $gitDir)) { Fixd "Added $gitDir to user PATH." }
    } else {
        Bad "Git is not installed."
        if ($Fix -and (Winget-Install 'Git.Git')) { Fixd "Installed Git."; $script:NeedNewShell = $true }
    }
} else { Ok "Git: $(& git --version)" }

# --- Python ----------------------------------------------------------------
function Find-Python {
    # Prefer 3.12 -> 3.11 -> 3.10 for prebuilt wheels, while supporting >=3.10 (incl. 3.13/3.14)
    foreach ($v in '3.12', '3.11', '3.10', '3.13', '3.14') {
        if (Get-Command py -ErrorAction SilentlyContinue) {
            $p = & py "-$v" -c "import sys;print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $p) { return $p.Trim() }
        }
    }
    $c = Get-Command python -ErrorAction SilentlyContinue
    if ($c -and $c.Source -notlike '*\WindowsApps\*') {
        $ver = & $c.Source -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
        if ($ver -in '3.10', '3.11', '3.12', '3.13', '3.14') { return $c.Source }
        Info "Found Python $ver at $($c.Source) (requires Python >=3.10)."
    }
    $parentRoots = @(
        "$env:LOCALAPPDATA\Programs\Python",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }
    foreach ($r in $parentRoots) {
        $dirs = Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^Python3(1[0-4])$' } |
            Sort-Object Name -Descending
        foreach ($dir in $dirs) {
            $exePath = Join-Path $dir.FullName 'python.exe'
            if (Test-Path -LiteralPath $exePath) { return $exePath }
        }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Bad "No usable Python >=3.10 found."
    if ($Fix -and (Winget-Install 'Python.Python.3.12')) {
        $py = Find-Python
        if ($py) { Fixd "Installed Python 3.12 at $py"; $script:NeedNewShell = $true }
    }
}
if ($py) {
    Ok "Python: $py ($(& $py --version))"
    $pyDir = Split-Path -Parent $py
    $cmdPy = Get-Command python -ErrorAction SilentlyContinue
    $onPath = ($null -ne $cmdPy) -and ($cmdPy.Source -notlike '*\WindowsApps\*')
    if (-not $onPath) {
        Bad "python.exe is not on PATH (use 'py' or the venv below, or fix PATH)."
        if ($Fix) {
            $a = Add-ToUserPath $pyDir
            $b = Add-ToUserPath (Join-Path $pyDir 'Scripts')
            if ($a -or $b) { Fixd "Added $pyDir and Scripts to user PATH (open a NEW terminal)." }
        }
    }
    $pipOk = & $py -m pip --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        Bad "pip is not available."
        if ($Fix) { & $py -m ensurepip --upgrade | Out-Null; if ($LASTEXITCODE -eq 0) { Fixd "Bootstrapped pip." } }
    } else { Ok "pip: $pipOk" }

    $bits = (& $py -c "import struct;print(struct.calcsize('P')*8)").Trim()
    Info "Python is $bits-bit"
}

# --- Visual C++ Redistributable -------------------------------------------
$arch = if ($py -and $bits -eq '32') { 'x86' } else { 'x64' }
$vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$arch"
$vc = Get-ItemProperty $vcKey -ErrorAction SilentlyContinue
if ($vc -and $vc.Installed -eq 1) {
    Ok "VC++ Redistributable ($arch) $($vc.Version)"
} else {
    Bad "VC++ 2015-2022 Redistributable ($arch) is missing. Python needs the $arch build."
    if ($Fix) {
        $id = if ($arch -eq 'x64') { 'Microsoft.VCRedist.2015+.x64' } else { 'Microsoft.VCRedist.2015+.x86' }
        if (Winget-Install $id) { Fixd "Installed VC++ Redistributable ($arch). A REBOOT may be required." }
    }
}
$dllDir = if ($arch -eq 'x86' -and [Environment]::Is64BitOperatingSystem) { 'SysWOW64' } else { 'System32' }
$dllPath = Join-Path (Join-Path $env:SystemRoot $dllDir) 'vcruntime140.dll'
if (Test-Path -LiteralPath $dllPath) {
    Ok "vcruntime140.dll present in $dllDir"
} else { Bad "vcruntime140.dll not found in $dllDir (reboot after installing the redistributable)." }

# --- venv + dependencies + CLI entrypoint ---------------------------------
$vpy = Join-Path (Join-Path $ProjectDir '.venv') 'Scripts\python.exe'
if ($py) {
    $venv = Join-Path $ProjectDir '.venv'
    $vcli = Join-Path $venv 'Scripts\junos-upgrader.exe'
    $venvValid = $false
    if (Test-Path -LiteralPath $vpy) {
        & $vpy -c "import sys; assert sys.version_info >= (3, 10)" 2>$null
        $venvValid = ($LASTEXITCODE -eq 0)
    }
    if (-not $venvValid) {
        Bad "Virtual environment missing or unhealthy ($venv)."
        if ($Fix) {
            & $py -m venv --clear $venv
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $vpy)) {
                $venvValid = $true
                Fixd "Created venv."
            }
        }
    } else { Ok "venv: $venv" }

    if ($venvValid) {
        & $vpy -c "import click, netmiko, paramiko, yaml, rich, junos_upgrader" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Ok "Dependencies and junos_upgrader import cleanly."
        } else {
            Bad "Dependencies or junos_upgrader package missing/failing to import."
            if ($Fix) {
                Info "Installing junos-switch-upgrader (wheels preferred)..."
                & $vpy -m pip install --upgrade pip 2>&1 | Out-Null
                & $vpy -m pip install --only-binary=:all: -e $ProjectDir
                if ($LASTEXITCODE -ne 0) {
                    Info "Retrying editable install allowing pure-Python sdist..."
                    & $vpy -m pip install -e $ProjectDir
                }
                & $vpy -c "import click, netmiko, paramiko, yaml, rich, junos_upgrader" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Fixd "Dependencies and junos_upgrader installed."
                } else {
                    Write-Host "`nImport error detail:" -ForegroundColor Red
                    & $vpy -c "import cryptography" 2>&1 | Select-Object -Last 5
                    Write-Host "If this mentions DLL load failed / VCRUNTIME: install the $arch VC++ Redistributable and REBOOT." -ForegroundColor Red
                }
            }
        }

        if (Test-Path -LiteralPath $vcli) {
            Ok "CLI entrypoint ready: $vcli"
        } else {
            Bad "CLI entrypoint missing: $vcli"
            if ($Fix) {
                & $vpy -m pip install --no-deps -e $ProjectDir 2>&1 | Out-Null
                if (Test-Path -LiteralPath $vcli) { Fixd "Registered $vcli" }
            }
        }
    }
}

# --- Local working directories --------------------------------------------
foreach ($sub in 'deliverables', 'firmware', 'manifests') {
    $p = Join-Path $ProjectDir $sub
    if (Test-Path -LiteralPath $p) {
        Ok "Directory present: $sub\"
    } else {
        Info "Directory missing: $sub\"
        if ($Fix) {
            New-Item -ItemType Directory -Force -Path $p | Out-Null
            Fixd "Created $sub\"
        }
    }
}

# --- Windows Firewall (inbound HTTP firmware server) -----------------------
$fwRuleName = "Junos-Switch-Upgrader HTTP ($HttpPort)"
try {
    $existingRule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Ok "Firewall rule present: $fwRuleName"
    } else {
        Info "No inbound firewall rule for TCP $HttpPort (needed if switches pull HTTP firmware from this laptop; SCP fallback works without it)."
        if ($FirewallRule) {
            if (-not $Fix) {
                Info "Skipping firewall rule in ASSESS ONLY mode; re-run elevated with -Fix -FirewallRule to apply."
            } else {
                try {
                    $fwParams = @{
                        DisplayName   = $fwRuleName
                        Direction     = 'Inbound'
                        Protocol      = 'TCP'
                        LocalPort     = $HttpPort
                        RemoteAddress = $FirewallRemoteAddress
                        Action        = 'Allow'
                        Profile       = @('Private', 'Domain')
                        ErrorAction   = 'Stop'
                    }
                    if (Test-Path -LiteralPath $vpy) {
                        $fwParams['Program'] = $vpy
                    }
                    New-NetFirewallRule @fwParams | Out-Null
                    Fixd "Added scoped inbound firewall rule for TCP $HttpPort (RemoteAddress=$FirewallRemoteAddress)."
                } catch {
                    Bad "Could not add firewall rule for TCP $HttpPort (run PowerShell as Administrator)."
                }
            }
        }
    }
} catch { Info "Windows Firewall status unavailable." }

# --- Defender (slowness) ---------------------------------------------------
try {
    $mp = Get-MpPreference -ErrorAction Stop
    if ($mp.DisableRealtimeMonitoring) { Ok "Defender real-time scan is off." }
    elseif ($mp.ExclusionPath -contains $ProjectDir) { Ok "Project folder excluded from Defender scans." }
    else {
        Info "Defender real-time scanning inspects every .py/.tgz file, slowing Python startup and firmware hashing."
        if ($DefenderExclusion) {
            if (-not $Fix) {
                Info "Skipping Defender exclusion in ASSESS ONLY mode; re-run elevated with -Fix -DefenderExclusion to apply."
            } else {
                try {
                    Add-MpPreference -ExclusionPath $ProjectDir -ErrorAction Stop
                    Fixd "Excluded $ProjectDir from Defender."
                } catch {
                    Bad "Could not add Defender exclusion (run as Administrator)."
                }
            }
        } else { Info "Re-run elevated with -Fix -DefenderExclusion to exclude the project folder (optional)." }
    }
} catch { Info "Defender status unavailable (third-party AV or no permission)." }

# --- Summary ---------------------------------------------------------------
$remaining = [Math]::Max(0, $script:Problems - $script:Fixed)
Write-Host "`n=== Summary: $script:Problems problem(s) found, $script:Fixed fixed, $remaining remaining ===" -ForegroundColor White
if (-not $Fix -and $script:Problems -gt 0) { Write-Host "Re-run with -Fix to repair." -ForegroundColor Yellow }
if ($script:NeedNewShell) { Write-Host "PATH changed: CLOSE and reopen this terminal before continuing." -ForegroundColor Yellow }
Write-Host "`nRun Junos-Switch-Upgrader with:"
Write-Host "  .\.venv\Scripts\junos-upgrader.exe discover --target 192.0.2.10 --credentials-file credentials.json --output deliverables\site-inventory.json"
Write-Host "  .\.venv\Scripts\junos-upgrader.exe topology --manifest deliverables\site-inventory.json --serve --port $HttpPort`n"

if ($remaining -gt 0) {
    exit 1
}
exit 0
