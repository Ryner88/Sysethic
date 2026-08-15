param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $SaoeArgs
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
if ($SaoeArgs.Count -eq 0) {
    $SaoeArgs = @("start")
}
& "venv\Scripts\python.exe" -m web.saaoe_cli @SaoeArgs
exit $LASTEXITCODE
