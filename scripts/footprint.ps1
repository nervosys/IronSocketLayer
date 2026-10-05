$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$output = Join-Path $repo 'target/footprint-object'
& cargo rustc -p iron-socket-layer --release --no-default-features --target thumbv7em-none-eabihf --target-dir $output -- -C lto=off -C linker-plugin-lto=no -C embed-bitcode=no --emit=obj,asm
if ($LASTEXITCODE -ne 0) { throw 'Cortex-M4 build failed' }
$deps = Join-Path $output 'thumbv7em-none-eabihf/release/deps'
# Earlier invocations can leave LLVM bitcode objects in this directory.
# Select a native ELF object explicitly rather than measuring bitcode.
$objects = @(Get-ChildItem $deps -Filter 'iron_socket_layer-*.o' | Where-Object {
    $header = [System.IO.File]::ReadAllBytes($_.FullName)
    $header.Length -ge 4 -and $header[0] -eq 0x7f -and $header[1] -eq 0x45 -and $header[2] -eq 0x4c -and $header[3] -eq 0x46
} | Sort-Object LastWriteTime -Descending)
if ($objects.Count -eq 0) { throw 'No ELF object found' }
$object = $objects[0]
& llvm-size $object.FullName | Tee-Object -FilePath (Join-Path $output 'sections.txt')
if ($LASTEXITCODE -ne 0) { throw 'llvm-size failed (LLVM tools must be on PATH)' }
Get-FileHash $object.FullName | Format-List | Out-File (Join-Path $output 'object-sha256.txt')
$asm = Get-Content ([System.IO.Path]::ChangeExtension($object.FullName, '.s'))
$start = ($asm | Select-String '^_.*record11content_end:$' | Select-Object -First 1).LineNumber
$end = ($asm | Select-String '^\s*\.size\s+_.*record11content_end' | Select-Object -First 1).LineNumber
if (-not $start -or -not $end) { throw 'Padding-scan assembly not found' }
$asm[($start - 1)..($end - 1)] | Set-Content (Join-Path $output 'padding-scan.s')
& cargo run -p iron-socket-layer --example footprint --target-dir target/regression-check |
    Tee-Object -FilePath (Join-Path $output 'inline-storage.txt')
if ($LASTEXITCODE -ne 0) { throw 'Host inline-storage measurement failed' }
Write-Output 'Object sections exclude IronCrypto, linking and LTO. Inline storage excludes heap allocations. Neither is a firmware flash/RAM budget.'
