$url = "http://localhost:8000/proxy/intercept"
$headers = @{
    "Content-Type" = "application/json"
}

# Test case 1: SQL Injection and XSS
$body1 = @{
    url = "https://target.com/v2/login"
    method = "POST"
    headers = @{
        "Content-Type" = "application/json"
    }
    body = @{
        username = "' OR '1'='1"
        password = "<script>alert('xss')</script>"
    }
    intercept = $true
} | ConvertTo-Json

# Test case 2: Open Redirect
$body2 = @{
    url = "https://target.com/v2/login"
    method = "POST"
    headers = @{
        "Content-Type" = "application/json"
    }
    body = @{
        username = "admin"
        password = "password"
        redirect = "http://evil.com"
    }
    intercept = $true
} | ConvertTo-Json

# Test case 3: Path Traversal
$body3 = @{
    url = "https://target.com/v2/login"
    method = "POST"
    headers = @{
        "Content-Type" = "application/json"
    }
    body = @{
        username = "admin"
        password = "password"
        file = "../../../etc/passwd"
    }
    intercept = $true
} | ConvertTo-Json

# Send test requests
Write-Host "Sending test case 1 (SQL Injection and XSS)..."
try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $body1
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
}

Write-Host "`nSending test case 2 (Open Redirect)..."
try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $body2
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
}

Write-Host "`nSending test case 3 (Path Traversal)..."
try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $body3
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
}

# Get vulnerability analysis
Write-Host "`nGetting vulnerability analysis..."
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/logger/vulnerabilities/severity"
    Write-Host "Vulnerability Analysis:"
    Write-Host $response.Content
} catch {
    Write-Host "Error getting vulnerability analysis: $_"
} 