# usbbackup build script (Windows / PowerShell).
#
# NOTE: This file is intentionally ASCII-only. Windows PowerShell 5.1 reads
# .ps1 files without a BOM using the ANSI codepage, which corrupts non-ASCII
# characters and breaks parsing. Keep all messages in English here.
#
# Usage:
#   .\build.ps1                    Build all 4 executables into .\dist\
#   .\build.ps1 -Version 0.2.0     Set the version string
#   .\build.ps1 -Test              Run gofmt + go vet + go test first
#   .\build.ps1 -Clean             Remove dist\ before building
#
# Standard library only: no network access, no dependency download.
# No packing/obfuscation/anti-AV processing is applied (see REQUIREMENTS.md G-07).

[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$Test,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$root    = $PSScriptRoot
$distDir = Join-Path $root 'dist'

# Locate go.exe: PATH first, then the isolated toolchain directory.
function Resolve-GoExe {
    $cmd = Get-Command go.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $versions = Join-Path $env:USERPROFILE '.workbuddy\binaries\go\versions'
    if (Test-Path $versions) {
        $found = Get-ChildItem $versions -Directory -ErrorAction SilentlyContinue |
                 Sort-Object Name -Descending |
                 ForEach-Object { Join-Path $_.FullName 'bin\go.exe' } |
                 Where-Object { Test-Path $_ } |
                 Select-Object -First 1
        if ($found) { return $found }
    }
    throw 'go.exe not found. Install Go 1.24+ and add it to PATH.'
}

$goExe = Resolve-GoExe

if (-not $Version) {
    $Version = (Get-Date -Format 'yyyy.MM.dd') + '-dev'
}

if ($Clean -and (Test-Path $distDir)) {
    Remove-Item $distDir -Recurse -Force
    Write-Host "cleaned $distDir"
}
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

Push-Location $root
try {
    Write-Host "go      : $goExe"
    Write-Host "version : $Version"

    if ($Test) {
        Write-Host ""
        Write-Host "[1/4] gofmt"
        & $goExe fmt ./...
        if ($LASTEXITCODE -ne 0) { throw 'gofmt failed' }

        Write-Host "[2/4] go vet"
        & $goExe vet ./...
        if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }

        Write-Host "[3/4] go test"
        & $goExe test ./...
        if ($LASTEXITCODE -ne 0) { throw 'go test failed' }
    }

    $commit = ''
    if (Test-Path (Join-Path $root '.git')) {
        $commit = (& git rev-parse --short HEAD 2>$null)
        if ($LASTEXITCODE -ne 0) { $commit = '' }
    }
    if (-not $commit) { $commit = 'nogit' }

    $buildTime = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')
    $buildUser = if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }

    $commonLd = @(
        '-s', '-w',
        '-X', "github.com/immml/UsbBackUP/internal/version.Version=$Version",
        '-X', "github.com/immml/UsbBackUP/internal/version.Commit=$commit",
        '-X', "github.com/immml/UsbBackUP/internal/version.BuildTime=$buildTime",
        '-X', "github.com/immml/UsbBackUP/internal/version.BuildUser=$buildUser"
    ) -join ' '

    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'

    # usbbackup is a background daemon: use the windowsgui subsystem so it does
    # not allocate a console window. The other three are interactive tools.
    $targets = @(
        @{ Name = 'usbbackup';  Pkg = './cmd/usbbackup';  Gui = $true  },
        @{ Name = 'usbkeygen'; Pkg = './cmd/usbkeygen'; Gui = $false },
        @{ Name = 'usbcomp';   Pkg = './cmd/usbcomp';   Gui = $false },
        @{ Name = 'usbunseal'; Pkg = './cmd/usbunseal'; Gui = $false }
    )

    Write-Host "[4/4] build"
    foreach ($t in $targets) {
        $out = Join-Path $distDir ($t.Name + '.exe')
        $ld = $commonLd
        if ($t.Gui) { $ld = $commonLd + ' -H=windowsgui' }

        $goArgs = @('build', '-trimpath', '-ldflags', $ld, '-o', $out, $t.Pkg)
        & $goExe @goArgs
        if ($LASTEXITCODE -ne 0) { throw "build failed: $($t.Name)" }
    }

    Write-Host ""
    Write-Host "build finished, artifacts in $distDir"
    Get-ChildItem $distDir -Filter *.exe |
        Select-Object Name, @{N='SizeMB';E={ '{0:N2}' -f ($_.Length/1MB) }} |
        Format-Table -AutoSize
}
finally {
    Pop-Location
}
