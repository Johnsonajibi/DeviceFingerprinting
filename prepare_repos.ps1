# Quick setup script to prepare all local repositories

$folders = @(
    "dual_qr_recovery",
    "quantum_resistant_crypto", 
    "forward_secure_encryption",
    "steganographic_qr",
    "dynamic_page_sizing",
    "security_testing"
)

$descriptions = @{
    "dual_qr_recovery" = "Initial commit: Revolutionary dual QR code recovery system"
    "quantum_resistant_crypto" = "Initial commit: Post-quantum cryptographic library"
    "forward_secure_encryption" = "Initial commit: Forward-secure page encryption"
    "steganographic_qr" = "Initial commit: Patent-pending steganographic QR system"
    "dynamic_page_sizing" = "Initial commit: Intelligent page size optimization"
    "security_testing" = "Initial commit: Comprehensive security testing framework"
}

Write-Host "🚀 Preparing QuantumVault Innovation Libraries for GitHub" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Write-Host "📁 Setting up $folder..." -ForegroundColor Yellow
        Push-Location $folder
        
        try {
            # Initialize git if not already done
            if (-not (Test-Path ".git")) {
                Write-Host "   🔧 Initializing Git repository..." -ForegroundColor Cyan
                git init 2>&1 | Out-Null
            } else {
                Write-Host "   ✅ Git repository already initialized" -ForegroundColor Green
            }
            
            # Create .gitignore
            if (-not (Test-Path ".gitignore")) {
                Write-Host "   📝 Creating .gitignore..." -ForegroundColor Cyan
                $gitignoreContent = @"
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

# Security sensitive files
*.key
*.pem
*.p12
vault_token.hash
vault_config.json
"@
                $gitignoreContent | Out-File -FilePath ".gitignore" -Encoding UTF8
            } else {
                Write-Host "   ✅ .gitignore already exists" -ForegroundColor Green
            }
            
            # Add files and commit
            Write-Host "   📦 Adding files to Git..." -ForegroundColor Cyan
            git add . 2>&1 | Out-Null
            
            # Check if there are changes to commit
            $status = git status --porcelain 2>&1
            if ($status) {
                Write-Host "   💾 Creating initial commit..." -ForegroundColor Cyan
                git commit -m $descriptions[$folder] 2>&1 | Out-Null
                Write-Host "   ✅ $folder ready for GitHub!" -ForegroundColor Green
            } else {
                Write-Host "   ✅ $folder already committed" -ForegroundColor Green
            }
            
        } catch {
            Write-Host "   ❌ Error setting up $folder`: $($_.Exception.Message)" -ForegroundColor Red
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "❌ $folder not found" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "🎉 All repositories prepared for GitHub!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Go to GitHub.com and create these PRIVATE repositories:" -ForegroundColor White
Write-Host "   • dual-qr-password-recovery" -ForegroundColor Gray
Write-Host "   • post-quantum-crypto-library" -ForegroundColor Gray
Write-Host "   • forward-secure-encryption" -ForegroundColor Gray
Write-Host "   • encrypted-data-in-qr-codes" -ForegroundColor Gray
Write-Host "   • dynamic-data-storage-optimizer" -ForegroundColor Gray
Write-Host "   • crypto-security-testing" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Then connect each local repository to GitHub using:" -ForegroundColor White
Write-Host "   See MANUAL_WEB_SETUP.md for detailed instructions" -ForegroundColor Gray
Write-Host ""
