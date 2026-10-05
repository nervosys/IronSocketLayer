param(
    [ValidateRange(1, 86400)][int]$Seconds = 600,
    [ValidateSet('messages', 'records', 'pki', 'tls_server', 'tls_client', 'quic_server')]
    [string[]]$Targets = @('messages', 'records', 'pki', 'tls_server', 'tls_client', 'quic_server')
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$output = Join-Path $repo 'target/fuzz-campaign'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$env:CARGO_TARGET_DIR = Join-Path $repo 'target/regression-check'
# The seed generator writes relative to cwd, so invoke it from fuzz/.
Push-Location (Join-Path $repo 'fuzz')
try {
    & cargo run --bin seed-corpus
    if ($LASTEXITCODE -ne 0) { throw 'Corpus generation/replay failed' }
} finally { Pop-Location }
Push-Location $repo
try {
    foreach ($target in $Targets) {
        $log = Join-Path $output "$target.log"
        & cargo +nightly fuzz run --fuzz-dir fuzz -O $target -- "-max_total_time=$Seconds" -timeout=10 -print_final_stats=1 *> $log
        if ($LASTEXITCODE -ne 0) { throw "Fuzz target $target failed; inspect $log and fuzz/artifacts/$target" }
        if (-not (Select-String -LiteralPath $log -Pattern '^Done \d+ runs in \d+ second')) {
            throw "Fuzz target $target did not finish its campaign: $log"
        }
        Get-Content $log -Tail 7
    }
} finally { Pop-Location }
Write-Output "Campaign logs: $output"
