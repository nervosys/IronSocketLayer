param([switch]$RequirementsOnly, [switch]$ReportOnly)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$label = if ($RequirementsOnly) { 'requirements' } else { 'whole-suite' }
$output = Join-Path $repo "target/coverage-$label"
New-Item -ItemType Directory -Force -Path $output | Out-Null
$env:CARGO_TARGET_DIR = $output
$env:CARGO_BUILD_BUILD_DIR = Join-Path $output 'llvm-cov-target'
$coverageArgs = @('+nightly', 'llvm-cov', '-p', 'ironsocketlayer', '--branch', '--no-report')
if ($RequirementsOnly) {
    $traced = @{}
    foreach ($line in Get-Content docs/TRACEABILITY.md) {
        if ($line -match '^\| REQ-' -and $line -match '\| Test \|') {
            foreach ($match in [regex]::Matches($line, '::([a-zA-Z0-9_]+)')) {
                $traced[$match.Groups[1].Value] = $true
            }
        }
    }
    $listed = & cargo test -p ironsocketlayer --lib --tests -- --list
    if ($LASTEXITCODE -ne 0) { throw 'Cannot list tests' }
    $skip = @()
    foreach ($line in $listed) {
        if ($line -match '^(.+): test$') {
            $testName = $Matches[1]
            $leafName = ($testName -split '::')[-1]
            if (-not $traced.ContainsKey($leafName)) { $skip += @('--skip', $testName) }
        }
    }
    $coverageArgs += @('--lib', '--tests', '--') + $skip
    $traced.Keys | Sort-Object | Set-Content (Join-Path $output 'traced-tests.txt')
}
if (-not $ReportOnly) {
    # Profiles from an earlier run would be merged with this one's and mapped
    # onto source that has since changed: start from none.
    if (Test-Path $env:CARGO_BUILD_BUILD_DIR) {
        Get-ChildItem $env:CARGO_BUILD_BUILD_DIR -Filter '*.profraw' -Recurse | Remove-Item -Force
    }
    & cargo @coverageArgs
    if ($LASTEXITCODE -ne 0) { throw 'Coverage test run failed' }
}
$sysroot = & rustc +nightly --print sysroot
$hostTriple = ((& rustc +nightly -vV) | Select-String '^host: ').ToString().Substring(6)
$llvm = Join-Path $sysroot "lib/rustlib/$hostTriple/bin"
$profiles = @(Get-ChildItem $env:CARGO_BUILD_BUILD_DIR -Filter '*.profraw' -Recurse | ForEach-Object FullName)
if ($profiles.Count -eq 0) { throw 'No execution profiles were produced' }
$profile = Join-Path $output 'merged.profdata'
& (Join-Path $llvm 'llvm-profdata.exe') merge -sparse @profiles -o $profile
if ($LASTEXITCODE -ne 0) { throw 'Profile merge failed' }
# cargo-llvm-cov 0.8.4 misses test executables in newer Cargo build layouts.
# Locate them directly, restricting objects to this library's tests.
# Test binaries are named after tests/*.rs, so new ones are included without
# editing this script.
$binaries = @('ironsocketlayer') + @(Get-ChildItem crates/ironsocketlayer/tests -Filter '*.rs' | ForEach-Object BaseName)
$binaryPattern = '^(' + (($binaries | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')-'
$objects = @(Get-ChildItem $output -Filter '*.exe' -Recurse | Where-Object {
    $_.FullName -match '[\\/]build[\\/]ironsocketlayer[\\/]' -or
    ($_.DirectoryName -match '[\\/]deps$' -and $_.Name -match $binaryPattern)
} | ForEach-Object { '--object=' + $_.FullName })
if ($objects.Count -eq 0) { throw 'No instrumented test executables found' }
$common = $objects + @("--instr-profile=$profile", '--ignore-filename-regex=(tests|IronCrypto|registry|rustc)')
& (Join-Path $llvm 'llvm-cov.exe') report @common --show-branch-summary |
    Tee-Object -FilePath (Join-Path $output 'summary.txt')
if ($LASTEXITCODE -ne 0) { throw 'Coverage report failed' }
& (Join-Path $llvm 'llvm-cov.exe') export @common |
    Set-Content -Encoding utf8 (Join-Path $output 'coverage.json')
if ($LASTEXITCODE -ne 0) { throw 'Coverage export failed' }
& (Join-Path $llvm 'llvm-cov.exe') show @common --format=html --show-branches=count ('--output-dir=' + (Join-Path $output 'html'))
if ($LASTEXITCODE -ne 0) { throw 'HTML report failed' }
Write-Output "Coverage artifacts: $output"
