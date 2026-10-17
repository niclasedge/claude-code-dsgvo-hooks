$credential = Get-Credential
$token = Invoke-RestMethod -Uri "https://auth.example.com/token" -Method POST
$env:API_KEY = "sk-fake-key-for-testing-only"
