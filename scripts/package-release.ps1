<#
.SYNOPSIS
    Builds the release and packs it: portable zip, NSIS installer, CycloneDX SBOMs, SHA-256 checksums.

.DESCRIPTION
    The release workflow and a developer run the same script, so what CI publishes is what runs here.
    It builds pcsleuth.exe and pcsleuth-recorder.exe (cargo, release) and pcsleuth-app.exe plus its
    installer (Tauri), then writes to -Out:

      pcsleuth-<version>-windows-x64.zip            the three executables, LICENSE, README.md
      pcsleuth-<version>-windows-x64-setup.exe      NSIS installer, per machine (Program Files)
      pcsleuth-<version>-sbom.cdx.json              CycloneDX 1.5 for pcsleuth.exe
      pcsleuth-recorder-<version>-sbom.cdx.json     ... for pcsleuth-recorder.exe
      pcsleuth-app-<version>-sbom.cdx.json          ... for pcsleuth-app.exe (the Rust side)
      pcsleuth-app-frontend-<version>-sbom.cdx.json ... for the page's bundled JavaScript
      SHA256SUMS.txt                                 `sha256sum -c` format, covers every file above

    Before it zips anything it runs the no-network test on the exact files it is about to ship. After
    it checks its own output: every checksum, the zip contents, and that the packed pcsleuth.exe starts.
    It does not run the installer (installing needs elevation) and signs nothing; signing is the
    owner's decision.

    Needs on PATH: cargo, node and npm, and cargo-cyclonedx
    (cargo install cargo-cyclonedx --locked --version 0.5.9). The Tauri CLI is fetched by npm at the
    version pinned below. Tauri downloads the NSIS toolset on first use.

    A '!' in a path is harmless to Tauri 2.12.4's NSIS build: it was tried in the tool cache (the
    profile folder), in the hooks file and a resource path, and in the cargo target folder.

.PARAMETER Tag
    The release tag, v<workspace version> with an optional -suffix, for example v0.1.0 or v0.1.0-rc1.
    The part before the suffix must equal the workspace version and the version in tauri.conf.json,
    so a tag cannot ship the wrong build.

.PARAMETER Out
    Output folder. Default: pcsleuth-dist inside the cargo target folder, which git ignores.

.PARAMETER WebView2
    How the installer gets the WebView2 runtime. 'bootstrapper' (default) embeds Microsoft's small
    bootstrapper: Windows 11 already has the runtime, so nothing is downloaded there, and a PC
    without it downloads it from Microsoft. 'offline' embeds the full runtime installer (about
    170 MB more) so installing never downloads.

.PARAMETER SkipBuild
    Reuse what the last run built (cargo, npm and Tauri), for repeated local runs.

.EXAMPLE
    powershell -NoProfile -File scripts\package-release.ps1 -Tag v0.1.0 -Out D:\scratch\dist
#>
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$Out,
    [ValidateSet('bootstrapper', 'offline')][string]$WebView2 = 'bootstrapper',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$TauriCli = '2.12.4'
$Root = Split-Path -Parent $PSScriptRoot
$Utf8 = New-Object Text.UTF8Encoding($false)

function Step([string]$text) { Write-Host "==> $text" }

# Runs a native command and stops the script on a non-zero exit code.
function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') exited with $LASTEXITCODE" }
}

if ($Tag -notmatch '^v(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$') {
    throw "Tag '$Tag' is not v<major>.<minor>.<patch> with an optional -suffix"
}
$Core = $Matches[1]
$Version = $Tag.Substring(1)

Push-Location $Root
try {
    $meta = (& cargo metadata --format-version 1 --no-deps --locked) | Out-String | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $workspace = ($meta.packages | Where-Object { $_.name -eq 'pcsleuth-cli' }).version
    if ($workspace -ne $Core) { throw "Tag $Tag does not match the workspace version $workspace" }
    $tauriVersion = (Get-Content (Join-Path $Root 'app\src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
    if ($tauriVersion -ne $Core) { throw "tauri.conf.json says $tauriVersion, the workspace says $Core" }
    $Target = $meta.target_directory
    $Bins = Join-Path $Target 'release'
    $App = Join-Path $Root 'app'
    if (-not $Out) { $Out = Join-Path $Target 'pcsleuth-dist' }
    if (-not [IO.Path]::IsPathRooted($Out)) { $Out = Join-Path (Get-Location) $Out }
    if (-not (Get-Command cargo-cyclonedx -ErrorAction SilentlyContinue)) {
        throw 'cargo-cyclonedx is missing: cargo install cargo-cyclonedx --locked --version 0.5.9'
    }

    if (-not $SkipBuild) {
        Step 'frontend: npm ci'
        Push-Location $App
        try { Run npm @('ci') } finally { Pop-Location }

        Step 'cargo build --release (pcsleuth.exe, pcsleuth-recorder.exe)'
        Run cargo @('build', '--release', '--locked', '-p', 'pcsleuth-cli', '-p', 'pcsleuth-recorder')

        Step 'Tauri build: pcsleuth-app.exe and the NSIS installer'
        # Resources are copied into the install folder, so the app finds pcsleuth.exe beside itself
        # and the recorder lands in Program Files, where its service may register from.
        $webview = if ($WebView2 -eq 'offline') { 'offlineInstaller' } else { 'embedBootstrapper' }
        $config = @{
            bundle = @{
                targets   = @('nsis')
                resources = @{
                    (Join-Path $Bins 'pcsleuth.exe')          = 'pcsleuth.exe'
                    (Join-Path $Bins 'pcsleuth-recorder.exe') = 'pcsleuth-recorder.exe'
                }
                windows   = @{
                    webviewInstallMode = @{ type = $webview; silent = $true }
                    nsis               = @{
                        installMode    = 'perMachine'
                        installerHooks = (Join-Path $PSScriptRoot 'installer-hooks.nsh')
                    }
                }
            }
        }
        $configFile = Join-Path ([IO.Path]::GetTempPath()) ("pcsleuth-tauri-" + [Guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllText($configFile, ($config | ConvertTo-Json -Depth 8), $Utf8)
        Remove-Item -Recurse -Force (Join-Path $Bins 'bundle\nsis') -ErrorAction SilentlyContinue
        try {
            Push-Location $App
            try {
                Run npx @('--yes', "@tauri-apps/cli@$TauriCli", 'build', '--bundles', 'nsis', '--config', $configFile)
            }
            finally { Pop-Location }
        }
        finally { Remove-Item -Force $configFile -ErrorAction SilentlyContinue }
    }
    foreach ($exe in 'pcsleuth.exe', 'pcsleuth-recorder.exe', 'pcsleuth-app.exe') {
        if (-not (Test-Path (Join-Path $Bins $exe))) { throw "$exe is not in $Bins" }
    }
    $installers = @(Get-ChildItem (Join-Path $Bins 'bundle\nsis') -Filter "pcsleuth_${Core}_x64-setup.exe" -ErrorAction SilentlyContinue)
    if ($installers.Count -ne 1) { throw "Expected one pcsleuth_${Core}_x64-setup.exe in $Bins\bundle\nsis" }

    if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
    New-Item -ItemType Directory -Path $Out | Out-Null

    $folder = "pcsleuth-$Version-windows-x64"
    $stage = Join-Path $Out "stage\$folder"
    New-Item -ItemType Directory -Path $stage | Out-Null
    foreach ($file in (Join-Path $Bins 'pcsleuth.exe'), (Join-Path $Bins 'pcsleuth-recorder.exe'),
        (Join-Path $Bins 'pcsleuth-app.exe'), (Join-Path $Root 'LICENSE'), (Join-Path $Root 'README.md')) {
        Copy-Item $file $stage
    }

    Step 'no network code in the files that ship'
    $env:PCSLEUTH_SCAN_PREBUILT = $stage
    try { Run cargo @('test', '-p', 'pcsleuth-cli', '--test', 'no_network', '--locked') }
    finally { Remove-Item Env:PCSLEUTH_SCAN_PREBUILT -ErrorAction SilentlyContinue }

    Step 'portable zip and installer'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Join-Path $Out "$folder.zip"
    # Entry names are built here with '/', as the zip format requires; Windows PowerShell 5.1's
    # CreateFromDirectory would write '\'.
    $archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        foreach ($file in Get-ChildItem $stage -File) {
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName,
                "$folder/$($file.Name)", [IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally { $archive.Dispose() }
    Remove-Item -Recurse -Force (Join-Path $Out 'stage')
    Copy-Item $installers[0].FullName (Join-Path $Out "$folder-setup.exe")

    Step 'CycloneDX SBOMs'
    try {
        # One run writes a file per binary of every workspace member next to its Cargo.toml.
        Run cargo @('cyclonedx', '--format', 'json', '--describe', 'binaries', '--spec-version', '1.5')
        $sboms = @{
            'crates\cli\pcsleuth_bin.cdx.json'               = "pcsleuth-$Version-sbom.cdx.json"
            'crates\recorder\pcsleuth-recorder_bin.cdx.json' = "pcsleuth-recorder-$Version-sbom.cdx.json"
            'app\src-tauri\pcsleuth-app_bin.cdx.json'        = "pcsleuth-app-$Version-sbom.cdx.json"
        }
        foreach ($from in $sboms.Keys) {
            Copy-Item (Join-Path $Root $from) (Join-Path $Out $sboms[$from])
        }
    }
    finally {
        Get-ChildItem -Path (Join-Path $Root 'crates'), (Join-Path $Root 'eval'), (Join-Path $Root 'app\src-tauri') -Recurse -Filter '*.cdx.json' |
            Remove-Item -Force
    }
    # The page's own dependencies, as shipped in the bundled JavaScript (development tools excluded).
    Push-Location $App
    try {
        $frontend = (& npm sbom --sbom-format cyclonedx --sbom-type application --omit dev) | Out-String
        if ($LASTEXITCODE -ne 0) { throw 'npm sbom failed' }
    }
    finally { Pop-Location }
    [IO.File]::WriteAllText((Join-Path $Out "pcsleuth-app-frontend-$Version-sbom.cdx.json"), $frontend, $Utf8)

    Step 'SHA256SUMS.txt'
    $lines = foreach ($file in Get-ChildItem $Out -File | Sort-Object Name) {
        '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLowerInvariant(), $file.Name
    }
    [IO.File]::WriteAllText((Join-Path $Out 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"), $Utf8)

    Step 'checking the output'
    foreach ($line in Get-Content (Join-Path $Out 'SHA256SUMS.txt')) {
        $hash, $name = $line -split ' \*', 2
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Out $name)).Hash.ToLowerInvariant()
        if ($actual -ne $hash) { throw "Checksum mismatch for $name" }
    }
    $setup = Join-Path $Out "$folder-setup.exe"
    $magic = [IO.File]::ReadAllBytes($setup)[0..1]
    if ($magic[0] -ne 0x4D -or $magic[1] -ne 0x5A) { throw 'The installer is not a Windows executable' }
    $check = Join-Path ([IO.Path]::GetTempPath()) ("pcsleuth-package-" + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $check)
        $names = @(Get-ChildItem (Join-Path $check $folder) | ForEach-Object Name)
        $expected = 'LICENSE', 'pcsleuth-app.exe', 'pcsleuth-recorder.exe', 'pcsleuth.exe', 'README.md'
        if ($names.Count -ne $expected.Count -or @($expected | Where-Object { $names -cnotcontains $_ }).Count) {
            throw "Zip holds '$($names -join ', ')', expected '$($expected -join ', ')'"
        }
        Run (Join-Path $check "$folder\pcsleuth.exe") @('--help') | Out-Null
    }
    finally {
        Remove-Item -Recurse -Force $check -ErrorAction SilentlyContinue
    }

    Step "done: $Out"
    Get-ChildItem $Out | ForEach-Object { '{0,14:N0}  {1}' -f $_.Length, $_.Name }
}
finally {
    Pop-Location
}
