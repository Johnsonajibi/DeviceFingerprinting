$ErrorActionPreference = 'Stop'

$packageName = 'device-fingerprinting-pro'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found Python: $pythonVersion"
} catch {
    throw "Python 3.8+ is required but not found. Please install Python first."
}

# Install the package using pip
Write-Host "Installing DeviceFingerprint Pro..."
Start-ChocolateyProcessAsAdmin "python -m pip install device-fingerprinting-pro" -validExitCodes @(0)

Write-Host "DeviceFingerprint Pro has been successfully installed!"
Write-Host "You can now use: python -c 'from devicefingerprint import generate_device_fingerprint; print(generate_device_fingerprint())'"
