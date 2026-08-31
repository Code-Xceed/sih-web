# GovShield Extension Packager for Chrome Web Store / Edge Add-ons
$extensionDir = "$PSScriptRoot\extension"
$outputZip = "$PSScriptRoot\govshield-extension-v1.0.0.zip"

if (Test-Path $outputZip) {
    Remove-Item $outputZip -Force
}

Compress-Archive -Path "$extensionDir\*" -DestinationPath $outputZip -Force
Write-Host "? Extension packaged successfully at: $outputZip" -ForegroundColor Green
