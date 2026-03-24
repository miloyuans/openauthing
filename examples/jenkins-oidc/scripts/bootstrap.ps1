param(
    [string]$ComposeFile = "",
    [string]$TenantID = "71000000-0000-0000-0000-000000000001",
    [string]$TenantName = "Jenkins Demo Tenant",
    [string]$TenantSlug = "jenkins-demo",
    [string]$AppID = "72000000-0000-0000-0000-000000000001",
    [string]$AppName = "Jenkins Local",
    [string]$AppCode = "jenkins-local",
    [string]$ClientID = "jenkins-local",
    [string]$ClientSecret = "jenkins-local-secret",
    [string]$RedirectURI = "http://localhost:8081/securityRealm/finishLogin",
    [string]$PostLogoutRedirectURI = "http://localhost:8081/OicLogout",
    [string]$DemoUsername = "jenkins.demo",
    [string]$DemoEmail = "jenkins.demo@example.test",
    [string]$DemoPassword = "Secret123!",
    [string]$DemoDisplayName = "Jenkins Demo User"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $ComposeFile = Join-Path $PSScriptRoot "..\docker-compose.yml"
}
$ComposeFile = (Resolve-Path $ComposeFile).Path

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    & docker compose -f $ComposeFile @Args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($Args -join ' ')"
    }
}

function Wait-Http {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }

    throw "timeout waiting for $Url"
}

Write-Host "Starting Jenkins OIDC demo stack..."
Invoke-Compose -Args @("up", "-d", "postgres", "redis", "openauthing", "jenkins")

Write-Host "Applying migrations..."
$applyUp = "for file in /workspace/migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U openauthing -d openauthing -f `"$file`"; done"
Invoke-Compose -Args @("exec", "-T", "postgres", "sh", "-lc", $applyUp)

Write-Host "Waiting for openauthing health endpoint..."
Wait-Http -Url "http://localhost:8080/healthz"

Write-Host "Generating Argon2id hash for Jenkins client secret..."
$ClientSecretHash = (& docker compose -f $ComposeFile exec -T openauthing go run -mod=mod ./examples/jenkins-oidc/tools/hash_argon2id.go $ClientSecret).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ClientSecretHash)) {
    throw "failed to generate client secret hash"
}

Write-Host "Seeding Jenkins demo tenant, application and OIDC client..."
Invoke-Compose -Args @(
    "exec", "-T", "postgres",
    "psql",
    "-v", "ON_ERROR_STOP=1",
    "-U", "openauthing",
    "-d", "openauthing",
    "-v", "tenant_id=$TenantID",
    "-v", "tenant_name=$TenantName",
    "-v", "tenant_slug=$TenantSlug",
    "-v", "app_id=$AppID",
    "-v", "app_name=$AppName",
    "-v", "app_code=$AppCode",
    "-v", "app_homepage_url=http://localhost:8081/",
    "-v", "client_id=$ClientID",
    "-v", "client_secret_hash=$ClientSecretHash",
    "-v", "redirect_uri=$RedirectURI",
    "-v", "post_logout_redirect_uri=$PostLogoutRedirectURI",
    "-f", "/workspace/examples/jenkins-oidc/seed/jenkins_oidc_seed.sql"
)

Write-Host "Creating demo user through openauthing API..."
$payload = @{
    tenant_id    = $TenantID
    username     = $DemoUsername
    email        = $DemoEmail
    display_name = $DemoDisplayName
    password     = $DemoPassword
    status       = "active"
    source       = "local"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/users" -ContentType "application/json" -Body $payload | Out-Null
} catch {
    if ($_.Exception.Response -eq $null) {
        throw
    }

    $statusCode = [int]$_.Exception.Response.StatusCode
    if ($statusCode -ne 409) {
        throw
    }
}

Write-Host ""
Write-Host "Jenkins OIDC demo seed complete."
Write-Host "Jenkins URL: http://localhost:8081"
Write-Host "OIDC issuer: http://host.docker.internal:8080"
Write-Host "Client ID: $ClientID"
Write-Host "Client Secret: $ClientSecret"
Write-Host "Redirect URI: $RedirectURI"
Write-Host "Logout Redirect URI: $PostLogoutRedirectURI"
Write-Host "Demo user: $DemoUsername / $DemoPassword"
