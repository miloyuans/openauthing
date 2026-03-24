param(
    [string]$ComposeFile = "",
    [string]$ProviderIssuer = "http://host.docker.internal:8080",
    [string]$JumpServerBaseURL = "http://localhost:8082/",
    [string]$TenantID = "81000000-0000-0000-0000-000000000001",
    [string]$TenantName = "JumpServer Demo Tenant",
    [string]$TenantSlug = "jumpserver-demo",
    [string]$AppID = "82000000-0000-0000-0000-000000000001",
    [string]$AppName = "JumpServer Local",
    [string]$AppCode = "jumpserver-local",
    [string]$ClientID = "jumpserver-local",
    [string]$ClientSecret = "jumpserver-local-secret",
    [string]$GroupID = "83000000-0000-0000-0000-000000000001",
    [string]$RoleID = "84000000-0000-0000-0000-000000000001",
    [string]$DemoUsername = "jump.demo",
    [string]$DemoEmail = "jump.demo@example.test",
    [string]$DemoPassword = "Secret123!",
    [string]$DemoDisplayName = "JumpServer Demo User"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $ComposeFile = Join-Path $PSScriptRoot "..\docker-compose.yml"
}
$ComposeFile = (Resolve-Path $ComposeFile).Path

$jumpServerOrigin = ([System.Uri]$JumpServerBaseURL).GetLeftPart([System.UriPartial]::Authority)
$normalizedJumpServerBaseURL = ([System.Uri]$JumpServerBaseURL).ToString()
$redirectURI = "$($normalizedJumpServerBaseURL)core/auth/openid/callback/"
$postLogoutRedirectURI = "$($normalizedJumpServerBaseURL)core/auth/openid/logout/"

$env:OPENAUTHING_OIDC_ISSUER = $ProviderIssuer
$env:OPENAUTHING_HTTP_ALLOWED_ORIGINS = $jumpServerOrigin

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

function Get-OrCreateDemoUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantIDValue
    )

    $payload = @{
        tenant_id    = $TenantIDValue
        username     = $DemoUsername
        email        = $DemoEmail
        display_name = $DemoDisplayName
        password     = $DemoPassword
        status       = "active"
        source       = "local"
    } | ConvertTo-Json

    try {
        $created = Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/users" -ContentType "application/json" -Body $payload
        return $created.data.id
    } catch {
        if ($_.Exception.Response -eq $null) {
            throw
        }

        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($statusCode -ne 409) {
            throw
        }
    }

    $encodedUsername = [System.Uri]::EscapeDataString($DemoUsername)
    $lookupURL = "http://localhost:8080/api/v1/users?tenant_id=$TenantIDValue&username=$encodedUsername&limit=1&offset=0"
    $lookup = Invoke-RestMethod -Method Get -Uri $lookupURL
    if ($lookup.data.items.Count -lt 1) {
        throw "demo user already existed but could not be queried back"
    }

    return $lookup.data.items[0].id
}

Write-Host "Starting openauthing stack for JumpServer OIDC demo..."
Invoke-Compose -Args @("up", "-d", "postgres", "redis", "openauthing")

Write-Host "Applying migrations..."
$applyUp = "for file in /workspace/migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U openauthing -d openauthing -f `"$file`"; done"
Invoke-Compose -Args @("exec", "-T", "postgres", "sh", "-lc", $applyUp)

Write-Host "Waiting for openauthing health endpoint..."
Wait-Http -Url "http://localhost:8080/healthz"

Write-Host "Generating Argon2id hash for JumpServer client secret..."
$clientSecretHash = (& docker compose -f $ComposeFile exec -T openauthing go run -mod=mod ./examples/jumpserver-oidc/tools/hash_argon2id.go $ClientSecret).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($clientSecretHash)) {
    throw "failed to generate client secret hash"
}

Write-Host "Seeding JumpServer demo tenant, application and OIDC client..."
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
    "-v", "app_homepage_url=$normalizedJumpServerBaseURL",
    "-v", "client_id=$ClientID",
    "-v", "client_secret_hash=$clientSecretHash",
    "-v", "redirect_uri=$redirectURI",
    "-v", "post_logout_redirect_uri=$postLogoutRedirectURI",
    "-f", "/workspace/examples/jumpserver-oidc/seed/jumpserver_oidc_seed.sql"
)

Write-Host "Creating or locating demo user..."
$userID = Get-OrCreateDemoUser -TenantIDValue $TenantID

Write-Host "Seeding demo groups and roles claims..."
Invoke-Compose -Args @(
    "exec", "-T", "postgres",
    "psql",
    "-v", "ON_ERROR_STOP=1",
    "-U", "openauthing",
    "-d", "openauthing",
    "-v", "tenant_id=$TenantID",
    "-v", "group_id=$GroupID",
    "-v", "role_id=$RoleID",
    "-v", "user_id=$userID",
    "-f", "/workspace/examples/jumpserver-oidc/seed/jumpserver_claims_seed.sql"
)

Write-Host ""
Write-Host "JumpServer OIDC demo seed complete."
Write-Host "openauthing URL: http://localhost:8080"
Write-Host "Issuer: $ProviderIssuer"
Write-Host "Authorization Endpoint: $ProviderIssuer/oauth2/authorize"
Write-Host "Token Endpoint: $ProviderIssuer/oauth2/token"
Write-Host "Userinfo Endpoint: $ProviderIssuer/oauth2/userinfo"
Write-Host "End Session Endpoint: $ProviderIssuer/oauth2/logout"
Write-Host "Client ID: $ClientID"
Write-Host "Client Secret: $ClientSecret"
Write-Host "JumpServer callback URI: $redirectURI"
Write-Host "JumpServer logout URI: $postLogoutRedirectURI"
Write-Host "Demo user: $DemoUsername / $DemoPassword"
Write-Host "Demo groups claim: jump_ops"
Write-Host "Demo roles claim: jump_user"
