# 🚀 GitHub Repository Setup Script for QuantumVault Innovation Libraries
# This script creates private GitHub repositories for each individual library

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

Write-Host "🔧 Setting up GitHub repositories for QuantumVault Innovation Libraries..." -ForegroundColor Cyan
Write-Host ""

# Check if GitHub CLI is installed
try {
    $ghVersion = gh --version
    Write-Host "✅ GitHub CLI found: $($ghVersion -split "`n")[0]" -ForegroundColor Green
} catch {
    Write-Host "❌ GitHub CLI not found. Please install GitHub CLI first:" -ForegroundColor Red
    Write-Host "   Download from: https://cli.github.com/" -ForegroundColor Yellow
    Write-Host "   Or run: winget install GitHub.cli" -ForegroundColor Yellow
    exit 1
}

# Check if user is authenticated
try {
    $authStatus = gh auth status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ GitHub CLI authenticated" -ForegroundColor Green
    } else {
        Write-Host "❌ Not authenticated with GitHub CLI" -ForegroundColor Red
        Write-Host "   Run: gh auth login" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "❌ GitHub CLI authentication check failed" -ForegroundColor Red
    Write-Host "   Run: gh auth login" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "🚀 Starting repository setup process..." -ForegroundColor Cyan
Write-Host ""

# Create each repository
foreach ($repo in $repositories) {
    Write-Host "📁 Processing: $($repo.Name)" -ForegroundColor Yellow
    
    # Check if folder exists
    if (-not (Test-Path $repo.Folder)) {
        Write-Host "   ❌ Folder $($repo.Folder) not found, skipping..." -ForegroundColor Red
        continue
    }
    
    # Navigate to library folder
    Push-Location $repo.Folder
    
    try {
        # Initialize Git repository
        Write-Host "   🔧 Initializing Git repository..." -ForegroundColor Cyan
        git init 2>&1 | Out-Null
        
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

# Virtual environments
venv/
env/
ENV/

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

# Environment variables
.env
.env.local

# Test coverage
.coverage
htmlcov/

# Temporary files
*.tmp
*.temp
"@ | Out-File -FilePath ".gitignore" -Encoding UTF8
        }
        
        # Add all files
        Write-Host "   📦 Adding files to Git..." -ForegroundColor Cyan
        git add . 2>&1 | Out-Null
        
        # Initial commit
        Write-Host "   💾 Creating initial commit..." -ForegroundColor Cyan
        git commit -m "Initial commit: $($repo.Description)" 2>&1 | Out-Null
        
        # Create GitHub repository
        Write-Host "   🌐 Creating GitHub repository..." -ForegroundColor Cyan
        $topicsString = $repo.Topics -join ","
        
        gh repo create $repo.Name `
            --description "$($repo.Description)" `
            --private `
            --source . `
            --remote origin `
            --push 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Repository created successfully!" -ForegroundColor Green
            Write-Host "   🔗 URL: https://github.com/$(gh api user --jq .login)/$($repo.Name)" -ForegroundColor Blue
            
            # Add topics using GitHub CLI
            Write-Host "   🏷️  Adding topics..." -ForegroundColor Cyan
            foreach ($topic in $repo.Topics) {
                gh repo edit $repo.Name --add-topic $topic 2>&1 | Out-Null
            }
        } else {
            Write-Host "   ❌ Failed to create repository" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        # Return to parent directory
        Pop-Location
    }
    
    Write-Host ""
}

Write-Host "🎉 Repository setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Summary of created repositories:" -ForegroundColor Cyan
foreach ($repo in $repositories) {
    if (Test-Path $repo.Folder) {
        Write-Host "   ✅ $($repo.Name)" -ForegroundColor Green
        Write-Host "      📁 Folder: $($repo.Folder)" -ForegroundColor Gray
        Write-Host "      🔗 https://github.com/$(gh api user --jq .login)/$($repo.Name)" -ForegroundColor Blue
    }
}

Write-Host ""
Write-Host "🔒 All repositories are set to PRIVATE by default" -ForegroundColor Yellow
Write-Host "📚 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Review each repository on GitHub" -ForegroundColor White
Write-Host "   2. Add collaborators if needed" -ForegroundColor White
Write-Host "   3. Configure repository settings" -ForegroundColor White
Write-Host "   4. Set up branch protection rules" -ForegroundColor White
Write-Host ""
