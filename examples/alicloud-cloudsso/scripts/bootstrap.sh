#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${EXAMPLE_DIR}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${EXAMPLE_DIR}/alicloud-cloudsso.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

: "${OPENAUTHING_OIDC_ISSUER:=http://host.docker.internal:8080}"
: "${ALICLOUD_CLOUDSSO_SAML_ENTITY_ID:?set ALICLOUD_CLOUDSSO_SAML_ENTITY_ID in ${ENV_FILE}}"
: "${ALICLOUD_CLOUDSSO_SAML_ACS_URL:?set ALICLOUD_CLOUDSSO_SAML_ACS_URL in ${ENV_FILE}}"
: "${ALICLOUD_CLOUDSSO_ACCESS_PORTAL_URL:?set ALICLOUD_CLOUDSSO_ACCESS_PORTAL_URL in ${ENV_FILE}}"
: "${ALICLOUD_CLOUDSSO_SCIM_ENDPOINT:?set ALICLOUD_CLOUDSSO_SCIM_ENDPOINT in ${ENV_FILE}}"

: "${ALICLOUD_CLOUDSSO_SAML_SLO_URL:=}"
: "${ALICLOUD_CLOUDSSO_SP_METADATA_XML_PATH:=}"
: "${TENANT_ID:=96000000-0000-0000-0000-000000000001}"
: "${TENANT_NAME:=Alibaba Cloud CloudSSO Demo Tenant}"
: "${TENANT_SLUG:=alicloud-cloudsso-demo}"
: "${SAML_APP_ID:=97000000-0000-0000-0000-000000000001}"
: "${SAML_APP_NAME:=Alibaba Cloud CloudSSO SAML}"
: "${SAML_APP_CODE:=alicloud-cloudsso-saml}"
: "${SCIM_APP_ID:=98000000-0000-0000-0000-000000000001}"
: "${SCIM_APP_NAME:=Alibaba Cloud CloudSSO SCIM}"
: "${SCIM_APP_CODE:=alicloud-cloudsso-scim}"
: "${GROUP_ID:=99000000-0000-0000-0000-000000000001}"
: "${GROUP_NAME:=Alibaba Cloud Platform}"
: "${GROUP_CODE:=alicloud-platform}"
: "${DEMO_USER_ID:=9a000000-0000-0000-0000-000000000001}"
: "${DEMO_USERNAME:=cloudsso.demo@example.test}"
: "${DEMO_EMAIL:=cloudsso.demo@example.test}"
: "${DEMO_DISPLAY_NAME:=Alibaba Cloud CloudSSO Demo User}"
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

echo "Starting openauthing stack for Alibaba Cloud CloudSSO demo..."
compose up -d postgres redis openauthing

echo "Applying migrations..."
compose exec -T postgres sh -lc 'for file in /workspace/migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U openauthing -d openauthing -f "$file"; done'

echo "Waiting for openauthing health endpoint..."
wait_http "http://localhost:8080/healthz"

echo "Generating Argon2id hash for the demo user password..."
demo_password_hash="$(compose exec -T openauthing go run -mod=mod ./examples/alicloud-cloudsso/tools/hash_argon2id.go "${DEMO_PASSWORD}" | tr -d '\r')"
if [[ -z "${demo_password_hash}" ]]; then
  echo "failed to generate demo password hash" >&2
  exit 1
fi

alicloud_cloudsso_sp_metadata_xml=""
if [[ -n "${ALICLOUD_CLOUDSSO_SP_METADATA_XML_PATH}" ]]; then
  alicloud_cloudsso_sp_metadata_xml="$(tr -d '\n' < "${ALICLOUD_CLOUDSSO_SP_METADATA_XML_PATH}")"
fi

echo "Seeding Alibaba Cloud CloudSSO SAML and SCIM demo configuration..."
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
  -v "scim_app_id=${SCIM_APP_ID}" \
  -v "scim_app_name=${SCIM_APP_NAME}" \
  -v "scim_app_code=${SCIM_APP_CODE}" \
  -v "group_id=${GROUP_ID}" \
  -v "group_name=${GROUP_NAME}" \
  -v "group_code=${GROUP_CODE}" \
  -v "demo_user_id=${DEMO_USER_ID}" \
  -v "demo_username=${DEMO_USERNAME}" \
  -v "demo_email=${DEMO_EMAIL}" \
  -v "demo_display_name=${DEMO_DISPLAY_NAME}" \
  -v "demo_password_hash=${demo_password_hash}" \
  -v "alicloud_cloudsso_access_portal_url=${ALICLOUD_CLOUDSSO_ACCESS_PORTAL_URL}" \
  -v "alicloud_cloudsso_saml_entity_id=${ALICLOUD_CLOUDSSO_SAML_ENTITY_ID}" \
  -v "alicloud_cloudsso_saml_acs_url=${ALICLOUD_CLOUDSSO_SAML_ACS_URL}" \
  -v "alicloud_cloudsso_saml_slo_url=${ALICLOUD_CLOUDSSO_SAML_SLO_URL}" \
  -v "alicloud_cloudsso_sp_metadata_xml=${alicloud_cloudsso_sp_metadata_xml}" \
  -v "alicloud_cloudsso_scim_endpoint=${ALICLOUD_CLOUDSSO_SCIM_ENDPOINT}" \
  -f /workspace/examples/alicloud-cloudsso/seed/alicloud_cloudsso_seed.sql

echo
echo "Alibaba Cloud CloudSSO demo seed complete."
echo "openauthing URL: http://localhost:8080"
echo "SAML app code: ${SAML_APP_CODE}"
echo "SCIM app code: ${SCIM_APP_CODE}"
echo "CloudSSO Entity ID: ${ALICLOUD_CLOUDSSO_SAML_ENTITY_ID}"
echo "CloudSSO ACS URL: ${ALICLOUD_CLOUDSSO_SAML_ACS_URL}"
echo "CloudSSO SCIM endpoint: ${ALICLOUD_CLOUDSSO_SCIM_ENDPOINT}"
echo "Demo user: ${DEMO_USERNAME} / ${DEMO_PASSWORD}"
echo "Demo group: ${GROUP_CODE}"
echo "Note: the CloudSSO SCIM token is intentionally not stored in openauthing."
