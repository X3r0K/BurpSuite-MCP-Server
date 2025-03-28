$url = "http://localhost:8000/proxy/intercept"
$headers = @{
    "Content-Type" = "application/json"
}
$body = @{
    url = "https://target.com/v2/login"
    method = "GET"
    headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    intercept = $true
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $body
    Write-Host "Status Code: $($response.StatusCode)"
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
} 