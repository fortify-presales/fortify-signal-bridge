# Loads classifier/selection variables for running the actions outside the container (needs python + PyYAML).
# Usage: . .\bin\Set-CollectorEnv.ps1 [-Classifiers all|none|id,id] [-ClassifiersDir path] [-Mode tag|filter] [-Python python]
param(
  [string]$Classifiers = 'all',
  [string]$ClassifiersDir = '',
  [ValidateSet('tag', 'filter')][string]$Mode = 'tag',
  [string]$Python = 'python'
)
$repo = Split-Path -Parent $PSScriptRoot
Get-ChildItem Env:COLLECTOR_* -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item "Env:$($_.Name)" }
$env:COLLECTOR_HOME = $repo
$env:CLASSIFIERS = $Classifiers
$env:CLASSIFIER_MODE = $Mode
if ($ClassifiersDir) { $env:CLASSIFIERS_DIR = (Resolve-Path $ClassifiersDir).Path } else { Remove-Item Env:CLASSIFIERS_DIR -ErrorAction SilentlyContinue }
$raw = & $Python "$repo\bin\prepare_config.py"
if ($LASTEXITCODE -ne 0) { throw "prepare_config.py failed" }
foreach ($pair in ($raw -split "`0" | Where-Object { $_ })) {
  $name, $value = $pair -split '=', 2
  if ($value) { Set-Item -Path "Env:$name" -Value $value }
}
