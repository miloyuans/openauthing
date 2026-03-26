#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${EXAMPLE_DIR}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${EXAMPLE_DIR}/mock-saml-sp.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

: "${OPENAUTHING_OIDC_ISSUER:=http://localhost:8080}"
: "${OPENAUTHING_SAML_IDP_ENTITY_ID:=http://localhost:8080/saml/idp/metadata}"

: "${MOCK_SAML_SP_BASE_URL:=http://localhost:8082}"
: "${MOCK_SAML_SP_ENTITY_ID:=${MOCK_SAML_SP_BASE_URL%/}/metadata}"
: "${MOCK_SAML_SP_ACS_URL:=${MOCK_SAML_SP_BASE_URL%/}/acs}"
: "${MOCK_SAML_SP_SLO_URL:=${MOCK_SAML_SP_BASE_URL%/}/slo}"
: "${MOCK_SAML_SP_IDP_SSO_URL:=http://localhost:8080/saml/idp/sso}"
: "${MOCK_SAML_SP_IDP_METADATA_URL:=http://openauthing:8080/saml/idp/metadata}"
: "${MOCK_SAML_SP_IDP_METADATA_BROWSER_URL:=http://localhost:8080/saml/idp/metadata}"
: "${MOCK_SAML_SP_DEFAULT_RELAY_STATE:=mock-saml-sp-demo}"

: "${TENANT_ID:=9b000000-0000-0000-0000-000000000001}"
: "${TENANT_NAME:=Mock SAML SP Demo Tenant}"
: "${TENANT_SLUG:=mock-saml-sp-demo}"
: "${SAML_APP_ID:=9c000000-0000-0000-0000-000000000001}"
: "${SAML_APP_NAME:=Mock SAML SP}"
: "${SAML_APP_CODE:=mock-saml-sp}"
: "${GROUP_ID:=9d000000-0000-0000-0000-000000000001}"
: "${GROUP_NAME:=Mock SAML Platform}"
: "${GROUP_CODE:=mock-saml-platform}"
: "${DEMO_USER_ID:=9e000000-0000-0000-0000-000000000001}"
: "${DEMO_USERNAME:=mocksaml.demo@example.test}"
: "${DEMO_EMAIL:=mocksaml.demo@example.test}"
: "${DEMO_DISPLAY_NAME:=Mock SAML Demo User}"
: "${DEMO_PASSWORD:=Secret123!}"

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

wait_http() {
  local url="$1"
  local deadline=$((SECONDS + 90))
  until curl -fsS "${url}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "timeout waiting for ${url}" >&2
      exit 1
    fi
    sleep 2
  done
}

echo "Starting openauthing stack for mock SAML SP demo..."
compose up -d postgres redis openauthing mock-saml-sp

echo "Applying migrations..."
compose exec -T postgres sh -lc 'for file in /workspace/migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U openauthing -d openauthing -f "$file"; done'

echo "Waiting for openauthing and mock-saml-sp health endpoints..."
wait_http "http://localhost:8080/healthz"
wait_http "http://localhost:8082/healthz"

echo "Generating Argon2id hash for the demo user password..."
demo_password_hash="$(compose exec -T openauthing go run -mod=mod ./examples/mock-saml-sp/tools/hash_argon2id.go "${DEMO_PASSWORD}" | tr -d '\r')"
if [[ -z "${demo_password_hash}" ]]; then
  echo "failed to generate demo password hash" >&2
  exit 1
fi

echo "Fetching mock SP metadata..."
mock_sp_metadata_xml="$(curl -fsS http://localhost:8082/metadata | tr -d '\n')"
if [[ -z "${mock_sp_metadata_xml}" ]]; then
  echo "failed to fetch mock SP metadata" >&2
  exit 1
fi

echo "Seeding mock SAML SP application and demo user..."
compose exec -T postgres psql \
  -v ON_ERROR_STOP=1 \
  -U openauthing \
  -d openauthing \
  -v "tenant_id=${TENANT_ID}" \
  -v "tenant_name=${TENANT_NAME}" \
  -v "tenant_slug=${TENANT_SLUG}" \
  -v "saml_app_id=${SAML_APP_ID}" \
  -v "saml_app_name=${SAML_APP_NAME}" \
  -v "saml_app_code=${SAML_APP_CODE}" \
  -v "group_id=${GROUP_ID}" \
  -v "group_name=${GROUP_NAME}" \
  -v "group_code=${GROUP_CODE}" \
  -v "demo_user_id=${DEMO_USER_ID}" \
  -v "demo_username=${DEMO_USERNAME}" \
  -v "demo_email=${DEMO_EMAIL}" \
  -v "demo_display_name=${DEMO_DISPLAY_NAME}" \
  -v "demo_password_hash=${demo_password_hash}" \
  -v "mock_sp_base_url=${MOCK_SAML_SP_BASE_URL}" \
  -v "mock_sp_entity_id=${MOCK_SAML_SP_ENTITY_ID}" \
  -v "mock_sp_acs_url=${MOCK_SAML_SP_ACS_URL}" \
  -v "mock_sp_slo_url=${MOCK_SAML_SP_SLO_URL}" \
  -v "mock_sp_metadata_xml=${mock_sp_metadata_xml}" \
  -f /workspace/examples/mock-saml-sp/seed/mock_saml_sp_seed.sql

echo
echo "Mock SAML SP demo seed complete."
echo "openauthing URL: http://localhost:8080"
echo "mock SP URL: http://localhost:8082"
echo "mock SP entity ID: ${MOCK_SAML_SP_ENTITY_ID}"
echo "mock SP ACS URL: ${MOCK_SAML_SP_ACS_URL}"
echo "mock SP app code: ${SAML_APP_CODE}"
echo "demo user: ${DEMO_USERNAME} / ${DEMO_PASSWORD}"
echo "demo group: ${GROUP_CODE}"
