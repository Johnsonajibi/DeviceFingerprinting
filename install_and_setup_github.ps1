# 🛠️ GitHub CLI Installation and Repository Setup

Write-Host "🚀 QuantumVault GitHub Repository Setup" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check if GitHub CLI is installed
$ghInstalled = $false
try {
    $ghVersion = gh --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ GitHub CLI is already installed" -ForegroundColor Green
        Write-Host "   Version: $($ghVersion -split "`n")[0]" -ForegroundColor Gray
        $ghInstalled = $true
    }
} catch {
    Write-Host "⚠️  GitHub CLI not found" -ForegroundColor Yellow
}

if (-not $ghInstalled) {
    Write-Host ""
    Write-Host "📥 Installing GitHub CLI..." -ForegroundColor Cyan
    
    # Try multiple installation methods
    $installMethods = @(
        @{
            Name = "Chocolatey"
            Command = "choco install gh"
            Check = { Get-Command choco -ErrorAction SilentlyContinue }
        },
        @{
            Name = "Scoop"
            Command = "scoop install gh"
            Check = { Get-Command scoop -ErrorAction SilentlyContinue }
        },
        @{
            Name = "Direct Download"
            Command = "Manual"
            Check = { $true }
        }
    )
    
    $installed = $false
    foreach ($method in $installMethods) {
        if (& $method.Check) {
            Write-Host "   Trying $($method.Name)..." -ForegroundColor Yellow
            
            if ($method.Name -eq "Direct Download") {
                Write-Host ""
                Write-Host "📋 Manual Installation Required:" -ForegroundColor Yellow
                Write-Host "   1. Download GitHub CLI from: https://cli.github.com/" -ForegroundColor White
                Write-Host "   2. Run the installer" -ForegroundColor White
                Write-Host "   3. Restart PowerShell" -ForegroundColor White
                Write-Host "   4. Run this script again" -ForegroundColor White
                Write-Host ""
                Write-Host "🔗 Direct download link:" -ForegroundColor Cyan
                Write-Host "   https://github.com/cli/cli/releases/latest/download/gh_windows_amd64.msi" -ForegroundColor Blue
                
                # Attempt to open the download page
                try {
                    Start-Process "https://cli.github.com/"
                    Write-Host "   ✅ Opened download page in browser" -ForegroundColor Green
                } catch {
                    Write-Host "   ⚠️  Please manually visit: https://cli.github.com/" -ForegroundColor Yellow
                }
                break
            } else {
                try {
                    Invoke-Expression $method.Command
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "   ✅ Installed via $($method.Name)" -ForegroundColor Green
                        $installed = $true
                        break
                    }
                } catch {
                    Write-Host "   ❌ $($method.Name) failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    if (-not $installed -and $method.Name -ne "Direct Download") {
        Write-Host ""
        Write-Host "❌ Automatic installation failed" -ForegroundColor Red
        Write-Host "📋 Please install manually:" -ForegroundColor Yellow
        Write-Host "   1. Visit: https://cli.github.com/" -ForegroundColor White
        Write-Host "   2. Download and install GitHub CLI" -ForegroundColor White
        Write-Host "   3. Restart PowerShell" -ForegroundColor White
        Write-Host "   4. Run this script again" -ForegroundColor White
        Write-Host ""
        return
    }
}

Write-Host ""
Write-Host "🔐 Authentication Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

# Check authentication status
try {
    $authStatus = gh auth status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Already authenticated with GitHub" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Not authenticated with GitHub" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "🔑 Please authenticate with GitHub CLI:" -ForegroundColor Cyan
        Write-Host "   Run: gh auth login" -ForegroundColor White
        Write-Host ""
        Write-Host "📋 Authentication steps:" -ForegroundColor Yellow
        Write-Host "   1. Choose 'GitHub.com'" -ForegroundColor White
        Write-Host "   2. Choose 'HTTPS'" -ForegroundColor White
        Write-Host "   3. Authenticate in browser" -ForegroundColor White
        Write-Host ""
        
        $authenticate = Read-Host "Would you like to authenticate now? (y/n)"
        if ($authenticate -eq 'y' -or $authenticate -eq 'Y') {
            gh auth login
        } else {
            Write-Host "⚠️  Please run 'gh auth login' before continuing" -ForegroundColor Yellow
            return
        }
    }
} catch {
    Write-Host "❌ Error checking authentication status" -ForegroundColor Red
    Write-Host "   Please run: gh auth login" -ForegroundColor Yellow
    return
}

Write-Host ""
Write-Host "📁 Repository Creation" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan

# Repository configurations
$repositories = @(
    @{
        Name = "dual-qr-password-recovery"
        Folder = "dual_qr_recovery"
        Description = "Revolutionary dual QR code recovery system with cryptographic isolation"
        Topics = @("cryptography", "qr-codes", "security", "recovery", "dual-factor")
    },
    @{
        Name = "post-quantum-crypto-library"
        Folder = "quantum_resistant_crypto"
        Description = "Post-quantum cryptographic library with SHA3-512 and timing attack protection"
        Topics = @("post-quantum", "cryptography", "sha3", "pbkdf2", "quantum-resistant")
    },
    @{
        Name = "forward-secure-encryption"
        Folder = "forward_secure_encryption"
        Description = "Forward-secure page encryption with epoch counters and selective re-encryption"
        Topics = @("forward-security", "encryption", "epoch-based", "aes-256", "temporal-security")
    },
    @{
        Name = "encrypted-data-in-qr-codes"
        Folder = "steganographic_qr"
        Description = "Patent-pending steganographic QR system using Reed-Solomon error correction"
        Topics = @("steganography", "qr-codes", "reed-solomon", "patent-pending", "encrypted-data")
    },
    @{
        Name = "dynamic-data-storage-optimizer"
        Folder = "dynamic_page_sizing"
        Description = "Intelligent page size optimization for cryptographic vault systems"
        Topics = @("optimization", "page-sizing", "performance", "vault-management", "adaptive-algorithms")
    },
    @{
        Name = "crypto-security-testing"
        Folder = "security_testing"
        Description = "Comprehensive security testing framework for cryptographic operations"
        Topics = @("security-testing", "timing-attacks", "cryptography", "validation", "test-framework")
    }
)

$createdRepos = @()
$failedRepos = @()

foreach ($repo in $repositories) {
    Write-Host ""
    Write-Host "📁 Processing: $($repo.Name)" -ForegroundColor Yellow
    Write-Host "   Folder: $($repo.Folder)" -ForegroundColor Gray
    
    if (-not (Test-Path $repo.Folder)) {
        Write-Host "   ❌ Folder $($repo.Folder) not found, skipping..." -ForegroundColor Red
        $failedRepos += $repo.Name
        continue
    }
    
    Push-Location $repo.Folder
    
    try {
        # Initialize Git if not already done
        if (-not (Test-Path ".git")) {
            Write-Host "   🔧 Initializing Git repository..." -ForegroundColor Cyan
            git init 2>&1 | Out-Null
        }
        
        # Create .gitignore if it doesn't exist
        if (-not (Test-Path ".gitignore")) {
            Write-Host "   📝 Creating .gitignore..." -ForegroundColor Cyan
            @"
# Python
__pycache__/
*.py[cod]
*`$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/
.venv/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Environment variables
.env
.env.local
.env.production

# Test coverage
.coverage
htmlcov/
.pytest_cache/

# Temporary files
*.tmp
*.temp

# Security
*.key
*.pem
*.p12
vault_token.hash
vault_config.json
"@ | Out-File -FilePath ".gitignore" -Encoding UTF8
        }
        
        # Add files and commit
        Write-Host "   📦 Adding files to Git..." -ForegroundColor Cyan
        git add . 2>&1 | Out-Null
        
        # Check if there are changes to commit
        $status = git status --porcelain 2>&1
        if ($status) {
            Write-Host "   💾 Creating initial commit..." -ForegroundColor Cyan
            git commit -m "Initial commit: $($repo.Description)" 2>&1 | Out-Null
        }
        
        # Create GitHub repository
        Write-Host "   🌐 Creating private GitHub repository..." -ForegroundColor Cyan
        
        $repoExists = $false
        try {
            gh repo view $repo.Name 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $repoExists = $true
                Write-Host "   ⚠️  Repository already exists on GitHub" -ForegroundColor Yellow
            }
        } catch {
            # Repository doesn't exist, which is what we want
        }
        
        if (-not $repoExists) {
            gh repo create $repo.Name `
                --description "$($repo.Description)" `
                --private `
                --source . `
                --remote origin `
                --push 2>&1 | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "   ✅ Repository created successfully!" -ForegroundColor Green
                
                # Add topics
                Write-Host "   🏷️  Adding topics..." -ForegroundColor Cyan
                foreach ($topic in $repo.Topics) {
                    gh repo edit $repo.Name --add-topic $topic 2>&1 | Out-Null
                }
                
                $createdRepos += $repo.Name
            } else {
                Write-Host "   ❌ Failed to create repository" -ForegroundColor Red
                $failedRepos += $repo.Name
            }
        } else {
            # Try to push to existing repository
            Write-Host "   📤 Pushing to existing repository..." -ForegroundColor Cyan
            git remote set-url origin "https://github.com/$(gh api user --jq .login)/$($repo.Name).git" 2>&1 | Out-Null
            git push -u origin main 2>&1 | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "   ✅ Pushed to existing repository!" -ForegroundColor Green
                $createdRepos += $repo.Name
            } else {
                Write-Host "   ❌ Failed to push to repository" -ForegroundColor Red
                $failedRepos += $repo.Name
            }
        }
        
    } catch {
        Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
        $failedRepos += $repo.Name
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "🎉 Repository Setup Complete!" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green
Write-Host ""

if ($createdRepos.Count -gt 0) {
    Write-Host "✅ Successfully created/updated repositories:" -ForegroundColor Green
    foreach ($repo in $createdRepos) {
        Write-Host "   📁 $repo" -ForegroundColor White
        Write-Host "      🔗 https://github.com/$(gh api user --jq .login)/$repo" -ForegroundColor Blue
    }
}

if ($failedRepos.Count -gt 0) {
    Write-Host ""
    Write-Host "❌ Failed repositories:" -ForegroundColor Red
    foreach ($repo in $failedRepos) {
        Write-Host "   📁 $repo" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "🔒 All repositories are set to PRIVATE" -ForegroundColor Yellow
Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Review each repository on GitHub" -ForegroundColor White
Write-Host "   2. Configure repository settings" -ForegroundColor White
Write-Host "   3. Add collaborators if needed" -ForegroundColor White
Write-Host "   4. Set up branch protection rules" -ForegroundColor White
Write-Host "   5. Enable security features (Dependabot, CodeQL)" -ForegroundColor White
Write-Host ""

# Show repository list command
Write-Host "🔍 To view your repositories:" -ForegroundColor Cyan
Write-Host "   gh repo list --private" -ForegroundColor White
Write-Host ""
