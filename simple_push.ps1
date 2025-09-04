# Simple GitHub Push Script

Write-Host "GitHub Repository Push Script" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Get GitHub username from user
$githubUsername = Read-Host "Enter your GitHub username"

if (-not $githubUsername) {
    Write-Host "ERROR: GitHub username is required!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Will push to these repositories:" -ForegroundColor Cyan
Write-Host "   https://github.com/$githubUsername/dual-qr-password-recovery" -ForegroundColor Gray
Write-Host "   https://github.com/$githubUsername/PM-PQC-crypto-library" -ForegroundColor Gray
Write-Host "   https://github.com/$githubUsername/forward-secure-encryption" -ForegroundColor Gray
Write-Host "   https://github.com/$githubUsername/encrypted-data-in-qr-codes" -ForegroundColor Gray
Write-Host "   https://github.com/$githubUsername/dynamic-data-storage-optimizer" -ForegroundColor Gray
Write-Host ""

$confirm = Read-Host "Have you created all 5 private repositories on GitHub.com? (y/n)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "Please create the repositories on GitHub.com first!" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting push process..." -ForegroundColor Cyan
Write-Host ""

$repositories = @(
    @{ Local = "dual_qr_recovery"; Remote = "dual-qr-password-recovery" },
    @{ Local = "quantum_resistant_crypto"; Remote = "PM-PQC-crypto-library" },
    @{ Local = "forward_secure_encryption"; Remote = "forward-secure-encryption" },
    @{ Local = "steganographic_qr"; Remote = "encrypted-data-in-qr-codes" },
    @{ Local = "dynamic_page_sizing"; Remote = "dynamic-data-storage-optimizer" }
)

$successful = @()
$failed = @()

foreach ($repo in $repositories) {
    Write-Host "Processing: $($repo.Local) -> $($repo.Remote)" -ForegroundColor Yellow
    
    if (-not (Test-Path $repo.Local)) {
        Write-Host "   ERROR: Local folder not found: $($repo.Local)" -ForegroundColor Red
        $failed += $repo.Remote
        continue
    }
    
    Push-Location $repo.Local
    
    # Commit any pending changes from manual edits
    Write-Host "   Committing any pending changes..." -ForegroundColor Cyan
    git add . 2>&1 | Out-Null
    git commit -m "Update README with detailed documentation and examples" 2>&1 | Out-Null
    
    # Remove existing remote if it exists
    Write-Host "   Setting up remote origin..." -ForegroundColor Cyan
    git remote remove origin 2>&1 | Out-Null
    
    # Add remote origin
    git remote add origin "https://github.com/$githubUsername/$($repo.Remote).git" 2>&1 | Out-Null
    
    # Rename branch to main and push
    Write-Host "   Pushing to GitHub..." -ForegroundColor Cyan
    git branch -M main 2>&1 | Out-Null
    git push -u origin main 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS: Pushed successfully!" -ForegroundColor Green
        Write-Host "   URL: https://github.com/$githubUsername/$($repo.Remote)" -ForegroundColor Blue
        $successful += $repo.Remote
    } else {
        Write-Host "   ERROR: Push failed" -ForegroundColor Red
        $failed += $repo.Remote
    }
    
    Pop-Location
    Write-Host ""
}

Write-Host "Push Process Complete!" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Write-Host ""

if ($successful.Count -gt 0) {
    Write-Host "Successfully pushed repositories:" -ForegroundColor Green
    foreach ($repo in $successful) {
        Write-Host "   $repo" -ForegroundColor White
        Write-Host "      https://github.com/$githubUsername/$repo" -ForegroundColor Blue
    }
    Write-Host ""
}

if ($failed.Count -gt 0) {
    Write-Host "Failed to push repositories:" -ForegroundColor Red
    foreach ($repo in $failed) {
        Write-Host "   $repo" -ForegroundColor White
    }
    Write-Host ""
}

Write-Host "All repositories are set to PRIVATE" -ForegroundColor Yellow
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "   1. Visit each repository on GitHub" -ForegroundColor White
Write-Host "   2. Add repository topics/tags" -ForegroundColor White
Write-Host "   3. Configure repository settings" -ForegroundColor White
Write-Host ""
