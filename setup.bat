# DDoS Detection Dashboard - Windows Setup Script
# Run this script in PowerShell

Write-Host "Setting up DDoS Detection Dashboard..." -ForegroundColor Green

# Create directory structure
Write-Host "`nCreating directory structure..." -ForegroundColor Yellow
$directories = @(
    "cmd\server",
    "cmd\simulator",
    "internal\ingestion",
    "internal\detection",
    "internal\mitigation",
    "internal\storage",
    "internal\models",
    "web",
    "docs"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "  Created: $dir" -ForegroundColor Gray
}

# Initialize Go module
Write-Host "`nInitializing Go module..." -ForegroundColor Yellow
go mod init github.com/nshruti113/ddos-detection-dashboard

# Download dependencies
Write-Host "`nDownloading dependencies..." -ForegroundColor Yellow
go get github.com/gin-gonic/gin@v1.9.1
go get github.com/google/uuid@v1.5.0
go get github.com/gorilla/websocket@v1.5.1
go get github.com/joho/godotenv@v1.5.1
go get github.com/lib/pq@v1.10.9
go get github.com/redis/go-redis/v9@v9.4.0

Write-Host "`n✅ Setup complete!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Copy the source files into the created directories"
Write-Host "2. Start Redis: docker run -d -p 6379:6379 redis:latest"
Write-Host "3. Run server: go run cmd\server\main.go"
Write-Host "4. Run simulator: go run cmd\simulator\main.go"
Write-Host "5. Open browser: http://localhost:8080"