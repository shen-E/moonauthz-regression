[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$script:Moon = (Get-Command moon -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$script:DemoTokens = @{ A = "demo-token-a"; B = "demo-token-b"; C = "demo-token-c" }
$script:DemoConfig = Get-Content -Raw (Join-Path $script:RepoRoot "examples/demo.json") | ConvertFrom-Json
$script:IdentityCount = @($script:DemoConfig.identities).Count
$script:ExpectedCrossCases = $script:IdentityCount * ($script:IdentityCount - 1)
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
  if ($baselines.Count -ne $script:IdentityCount -or @($baselines | Where-Object { -not $_.passed }).Count -ne 0) {
    throw "$Mode run did not pass every owner baseline request."
  }
  $crossCases = @($report.cases | Where-Object { $_.case -like "cross-*" })
  if ($crossCases.Count -ne $script:ExpectedCrossCases) { throw "$Mode run did not produce every cross-identity case." }

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
    foreach ($token in $script:DemoTokens.Values) {
      if ($content.Contains($token)) {
        throw "A generated artifact contains a demo credential: $($file.FullName)"
      }
    }
  }

  if ($Mode -eq "vulnerable") {
    $repros = @(Get-ChildItem -LiteralPath $outputDir -Filter "*.http" -File)
    if ($repros.Count -ne $script:ExpectedCrossCases) { throw "Vulnerable mode should produce a sanitized .http reproduction for each failing identity pair." }
    $placeholderPrefix = '$' + '{ENV:MOONAUTHZ_TOKEN_'
    foreach ($repro in $repros) {
      $content = [System.IO.File]::ReadAllText($repro.FullName)
      if (-not $content.Contains($placeholderPrefix)) { throw "The repro does not use an environment placeholder." }
    }
  }
  elseif (@(Get-ChildItem -LiteralPath $outputDir -Filter "*.http" -File).Count -ne 0) {
    throw "Safe mode unexpectedly produced failure reproductions."
  }
  Write-Host ("{0}: expected behavior verified (exit {1}); baselines={2}, cross-cases={3}." -f $Mode, $ExpectedExitCode, $script:IdentityCount, $script:ExpectedCrossCases)
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

function Copy-DemoConfig {
  return ($script:DemoConfig | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}

function Invoke-BoundaryConfig {
  param([string]$Name, [object]$Config, [int]$ExpectedExitCode)
  $relativeConfig = Join-Path (Join-Path $script:RelativeRunRoot "configs") "$Name.json"
  $configPath = Join-Path $script:RepoRoot $relativeConfig
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $configPath) | Out-Null
  Write-Utf8File -Path $configPath -Content ($Config | ConvertTo-Json -Depth 20)
  $relativeOutputDir = Join-Path (Join-Path $script:RelativeRunRoot "boundary") $Name
  $outputDir = Join-Path $script:RepoRoot $relativeOutputDir
  New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
  $logPath = Join-Path $script:LogsRoot "boundary-$Name.log"
  $null = Invoke-Moon -Arguments @("run", "--target", "native", "cmd/main", "--", "run", $relativeConfig, "--out", $relativeOutputDir) -LogPath $logPath -ExpectedExitCode $ExpectedExitCode
  $reportPath = Join-Path $outputDir "report.json"
  $report = $null
  if (Test-Path $reportPath) { $report = Get-Content -Raw $reportPath | ConvertFrom-Json }
  return [pscustomobject]@{ OutputDir = $outputDir; LogPath = $logPath; Report = $report }
}

function Invoke-BoundaryChecks {
  $server = Start-DemoServer -Mode safe
  $missingTokenName = "MOONAUTHZ_TOKEN_MISSING"
  $previousMissingToken = [Environment]::GetEnvironmentVariable($missingTokenName, "Process")
  try {
    $missingCredential = Copy-DemoConfig
    $missingCredential.identities[0].headers.Authorization = 'Bearer ${ENV:MOONAUTHZ_TOKEN_MISSING}'
    [Environment]::SetEnvironmentVariable($missingTokenName, $null, "Process")
    $missingResult = Invoke-BoundaryConfig -Name "missing-credential" -Config $missingCredential -ExpectedExitCode 2
    if (-not (Select-String -LiteralPath $missingResult.LogPath -Pattern "环境变量未设置: $missingTokenName" -Quiet)) {
      throw "Missing credentials did not produce the expected execution error."
    }

    $badBaselineStatus = Copy-DemoConfig
    $badBaselineStatus.identities[0].baseline_statuses = @(201)
    $baselineResult = Invoke-BoundaryConfig -Name "baseline-status-mismatch" -Config $badBaselineStatus -ExpectedExitCode 2
    if ($null -eq $baselineResult.Report -or $baselineResult.Report.exit_code -ne 2 -or @($baselineResult.Report.cases | Where-Object { $_.case -like "cross-*" }).Count -ne 0) {
      throw "An invalid baseline status must end the run with exit 2 before cross-identity checks."
    }

    $missingPointer = Copy-DemoConfig
    $missingPointer.identities[0].sensitive_json_pointers = @("/missing_field")
    $pointerResult = Invoke-BoundaryConfig -Name "missing-sensitive-field" -Config $missingPointer -ExpectedExitCode 2
    $firstBaseline = @($pointerResult.Report.cases | Where-Object { $_.case -eq "baseline-A" })[0]
    if ($null -eq $firstBaseline -or $firstBaseline.passed -or $pointerResult.Report.exit_code -ne 2) {
      throw "A missing baseline marker must be reported as an execution error."
    }

    $badDeniedStatus = Copy-DemoConfig
    $badDeniedStatus.denied_statuses = @(401)
    $deniedResult = Invoke-BoundaryConfig -Name "denied-status-mismatch" -Config $badDeniedStatus -ExpectedExitCode 1
    $crossCases = @($deniedResult.Report.cases | Where-Object { $_.case -like "cross-*" })
    if ($deniedResult.Report.exit_code -ne 1 -or $crossCases.Count -ne $script:ExpectedCrossCases -or @($crossCases | Where-Object { $_.passed -or @($_.leaks).Count -ne 0 }).Count -ne 0) {
      throw "A status outside the configured denied set must be reported as authorization test failures (exit 1), with no false leak marker."
    }
    $reproductions = @(Get-ChildItem -LiteralPath $deniedResult.OutputDir -Filter "*.http" -File)
    if ($reproductions.Count -ne $script:ExpectedCrossCases) {
      throw "A denied-status mismatch must save one sanitized reproduction per failed cross case."
    }
  }
  finally {
    [Environment]::SetEnvironmentVariable($missingTokenName, $previousMissingToken, "Process")
    Stop-DemoServer -Process $server
  }
  Write-Host "Execution-boundary checks passed: missing credentials, invalid baselines, missing fields, and denied-status mismatch."
}

$previousTokens = @{}
try {
  foreach ($identity in $script:DemoConfig.identities) {
    $name = $identity.name
    if (-not $script:DemoTokens.ContainsKey($name)) { throw "No demo token is configured for identity $name." }
    $envName = "MOONAUTHZ_TOKEN_$name"
    $previousTokens[$envName] = [Environment]::GetEnvironmentVariable($envName, "Process")
    [Environment]::SetEnvironmentVariable($envName, $script:DemoTokens[$name], "Process")
  }
  Write-Host "MoonAuthz Regression acceptance run: $script:RunId"
  Write-Host "Artifacts: $script:RunRoot"
  $null = Invoke-Moon -Arguments @("update") -LogPath (Join-Path $script:LogsRoot "moon-update.log") -ExpectedExitCode 0
  $null = Invoke-Moon -Arguments @("check", "--target", "native") -LogPath (Join-Path $script:LogsRoot "moon-check.log") -ExpectedExitCode 0
  $null = Invoke-Moon -Arguments @("test", "--target", "native") -LogPath (Join-Path $script:LogsRoot "moon-test.log") -ExpectedExitCode 0
  Invoke-Mode -Mode "safe" -ExpectedExitCode 0
  Invoke-Mode -Mode "vulnerable" -ExpectedExitCode 1
  Invoke-BoundaryChecks
  foreach ($file in @(Get-ChildItem -LiteralPath $script:RunRoot -File -Recurse)) {
    $content = [System.IO.File]::ReadAllText($file.FullName)
    foreach ($token in $script:DemoTokens.Values) {
      if ($content.Contains($token)) {
        throw "A generated artifact contains a demo credential: $($file.FullName)"
      }
    }
  }

  $summary = @"
# Acceptance run $script:RunId

- moon check --target native: passed.
- moon test --target native: passed.
- Safe API: all $script:IdentityCount owner baselines passed; all $script:ExpectedCrossCases cross-identity reads were denied; CLI exit code 0.
- Vulnerable API: all owner baselines passed; all cross-identity reads exposed protected markers; CLI exit code 1.
- Execution boundaries: missing credentials, baseline status mismatch, missing sensitive field, and denied-status mismatch returned the expected exit codes and report outcomes.
- Credential scan: passed for generated reports, logs, and reproductions.
- Safe report: safe/report.json
- Vulnerable report: vulnerable/report.json
- Sanitized reproductions: vulnerable/failure-1.http through vulnerable/failure-$($script:ExpectedCrossCases).http
"@
  Write-Utf8File -Path (Join-Path $script:RunRoot "SUMMARY.md") -Content $summary
  Write-Host ([Environment]::NewLine + "Acceptance passed. See $(Join-Path $script:RunRoot 'SUMMARY.md')")
}
finally {
  foreach ($envName in $previousTokens.Keys) {
    [Environment]::SetEnvironmentVariable($envName, $previousTokens[$envName], "Process")
  }
  Pop-Location
}

$global:LASTEXITCODE = 0
