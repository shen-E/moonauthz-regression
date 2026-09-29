[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$script:Moon = (Get-Command moon -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$script:DemoTokenA = "demo-token-a"
$script:DemoTokenB = "demo-token-b"
$script:RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$script:RelativeRunRoot = Join-Path "artifacts/acceptance" $script:RunId
$script:RunRoot = Join-Path $script:RepoRoot $script:RelativeRunRoot
$script:LogsRoot = Join-Path $script:RunRoot "logs"

New-Item -ItemType Directory -Force -Path $script:LogsRoot | Out-Null
Push-Location $script:RepoRoot

function Write-Utf8File {
  param([string]$Path, [string]$Content)
  [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-Moon {
  param([string[]]$Arguments, [string]$LogPath, [int]$ExpectedExitCode)
  Write-Host ([Environment]::NewLine + ("> moon {0}" -f ($Arguments -join " ")))
  $captured = & $script:Moon @Arguments 2>&1
  $actualExitCode = $LASTEXITCODE
  $lines = @($captured | ForEach-Object { $_.ToString() })
  Write-Utf8File -Path $LogPath -Content ($lines -join [Environment]::NewLine)
  $lines | ForEach-Object { Write-Host $_ }
  if ($actualExitCode -ne $ExpectedExitCode) {
    throw "moon $($Arguments -join ' ') returned $actualExitCode; expected $ExpectedExitCode. See $LogPath"
  }
  return $actualExitCode
}

function Assert-PortAvailable {
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 8095)
  try { $listener.Start() }
  catch { throw "127.0.0.1:8095 is already in use. Stop the process using the demo port and retry." }
  finally { $listener.Stop() }
}

function Start-DemoServer {
  param([ValidateSet("safe", "vulnerable")][string]$Mode)
  Assert-PortAvailable
  $stdout = Join-Path $script:LogsRoot "$Mode-server.stdout.log"
  $stderr = Join-Path $script:LogsRoot "$Mode-server.stderr.log"
  $process = Start-Process -FilePath $script:Moon -ArgumentList @("run", "--target", "native", "cmd/demo", "--", "--mode", $Mode) -WorkingDirectory $script:RepoRoot -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  while ([DateTime]::UtcNow -lt $deadline) {
    if ($process.HasExited) {
      $serverOutput = @()
      if (Test-Path $stdout) { $serverOutput += Get-Content $stdout }
      if (Test-Path $stderr) { $serverOutput += Get-Content $stderr }
      throw ("The {0} demo server stopped before readiness.{1}{2}" -f $Mode, [Environment]::NewLine, ($serverOutput -join [Environment]::NewLine))
    }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
      $client.Connect("127.0.0.1", 8095)
      Write-Host "Started $Mode demo server (PID $($process.Id))."
      return $process
    }
    catch { Start-Sleep -Milliseconds 250 }
    finally { $client.Dispose() }
  }
  try {
    if (-not $process.HasExited) {
      $process.Kill($true)
      $process.WaitForExit()
    }
  }
  finally { $process.Dispose() }
  throw "Timed out waiting for the $Mode demo server on 127.0.0.1:8095."
}

function Stop-DemoServer {
  param([System.Diagnostics.Process]$Process)
  try {
    if (-not $Process.HasExited) {
      try { $Process.Kill($true) }
      catch { if (-not $Process.HasExited) { throw } }
      if (-not $Process.HasExited) { $Process.WaitForExit() }
    }
  }
  finally { $Process.Dispose() }
}

function Assert-ModeReport {
  param([ValidateSet("safe", "vulnerable")][string]$Mode, [int]$ExpectedExitCode)
  $relativeOutputDir = Join-Path $script:RelativeRunRoot $Mode
  $outputDir = Join-Path $script:RepoRoot $relativeOutputDir
  $reportPath = Join-Path $outputDir "report.json"
  if (-not (Test-Path $reportPath)) { throw "The $Mode run did not produce $reportPath." }
  $report = Get-Content -Raw $reportPath | ConvertFrom-Json
  if ($report.exit_code -ne $ExpectedExitCode) { throw "$Mode report declares an unexpected exit code." }

  $baselines = @($report.cases | Where-Object { $_.case -like "baseline-*" })
  if ($baselines.Count -ne 2 -or @($baselines | Where-Object { -not $_.passed }).Count -ne 0) {
    throw "$Mode run did not pass both owner baseline requests."
  }
  $crossCases = @($report.cases | Where-Object { $_.case -like "cross-*" })
  if ($crossCases.Count -ne 2) { throw "$Mode run did not produce both cross-identity cases." }

  foreach ($case in $crossCases) {
    if ($Mode -eq "safe") {
      if (-not $case.passed -or @($case.leaks).Count -ne 0 -or $case.status -notin @(403, 404)) {
        throw "Safe mode did not block $($case.case) as expected."
      }
    }
    else {
      if ($case.passed -or @($case.leaks).Count -eq 0 -or $case.status -in @(403, 404)) {
        throw "Vulnerable mode did not expose a protected marker in $($case.case)."
      }
    }
  }

  foreach ($file in @(Get-ChildItem -LiteralPath $script:RunRoot -File -Recurse)) {
    $content = [System.IO.File]::ReadAllText($file.FullName)
    if ($content.Contains($script:DemoTokenA) -or $content.Contains($script:DemoTokenB)) {
      throw "A generated artifact contains a demo credential: $($file.FullName)"
    }
  }

  if ($Mode -eq "vulnerable") {
    $repros = @(Get-ChildItem -LiteralPath $outputDir -Filter "*.http" -File)
    if ($repros.Count -ne 2) { throw "Vulnerable mode should produce two sanitized .http reproductions." }
    $placeholderPrefix = '$' + '{ENV:MOONAUTHZ_TOKEN_'
    foreach ($repro in $repros) {
      $content = [System.IO.File]::ReadAllText($repro.FullName)
      if (-not $content.Contains($placeholderPrefix)) { throw "The repro does not use an environment placeholder." }
    }
  }
  elseif (@(Get-ChildItem -LiteralPath $outputDir -Filter "*.http" -File).Count -ne 0) {
    throw "Safe mode unexpectedly produced failure reproductions."
  }
  Write-Host ("{0}: expected behavior verified (exit {1}); baselines=2, cross-cases=2." -f $Mode, $ExpectedExitCode)
}

function Invoke-Mode {
  param([ValidateSet("safe", "vulnerable")][string]$Mode, [int]$ExpectedExitCode)
  $server = Start-DemoServer -Mode $Mode
  try {
    $relativeOutputDir = Join-Path $script:RelativeRunRoot $Mode
    $outputDir = Join-Path $script:RepoRoot $relativeOutputDir
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    $logPath = Join-Path $script:LogsRoot "$Mode-cli.log"
    $null = Invoke-Moon -Arguments @("run", "--target", "native", "cmd/main", "--", "run", "examples/demo.json", "--out", $relativeOutputDir) -LogPath $logPath -ExpectedExitCode $ExpectedExitCode
  }
  finally { Stop-DemoServer -Process $server }
  Assert-ModeReport -Mode $Mode -ExpectedExitCode $ExpectedExitCode
}

$previousTokenA = $env:MOONAUTHZ_TOKEN_A
$previousTokenB = $env:MOONAUTHZ_TOKEN_B
try {
  $env:MOONAUTHZ_TOKEN_A = $script:DemoTokenA
  $env:MOONAUTHZ_TOKEN_B = $script:DemoTokenB
  Write-Host "MoonAuthz Regression acceptance run: $script:RunId"
  Write-Host "Artifacts: $script:RunRoot"
  $null = Invoke-Moon -Arguments @("update") -LogPath (Join-Path $script:LogsRoot "moon-update.log") -ExpectedExitCode 0
  $null = Invoke-Moon -Arguments @("check", "--target", "native") -LogPath (Join-Path $script:LogsRoot "moon-check.log") -ExpectedExitCode 0
  Invoke-Mode -Mode "safe" -ExpectedExitCode 0
  Invoke-Mode -Mode "vulnerable" -ExpectedExitCode 1

  $summary = @"
# Acceptance run $script:RunId

- moon check --target native: passed.
- Safe API: both owner baselines passed; both cross-identity reads were denied; CLI exit code 0.
- Vulnerable API: both owner baselines passed; both cross-identity reads exposed protected markers; CLI exit code 1.
- Credential scan: passed for generated reports, logs, and reproductions.
- Safe report: safe/report.json
- Vulnerable report: vulnerable/report.json
- Sanitized reproductions: vulnerable/failure-1.http, vulnerable/failure-2.http
"@
  Write-Utf8File -Path (Join-Path $script:RunRoot "SUMMARY.md") -Content $summary
  Write-Host ([Environment]::NewLine + "Acceptance passed. See $(Join-Path $script:RunRoot 'SUMMARY.md')")
}
finally {
  if ($null -eq $previousTokenA) { Remove-Item Env:MOONAUTHZ_TOKEN_A -ErrorAction SilentlyContinue } else { $env:MOONAUTHZ_TOKEN_A = $previousTokenA }
  if ($null -eq $previousTokenB) { Remove-Item Env:MOONAUTHZ_TOKEN_B -ErrorAction SilentlyContinue } else { $env:MOONAUTHZ_TOKEN_B = $previousTokenB }
  Pop-Location
}
