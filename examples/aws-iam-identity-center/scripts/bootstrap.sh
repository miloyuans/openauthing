#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${EXAMPLE_DIR}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${EXAMPLE_DIR}/aws-iam-identity-center.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

: "${OPENAUTHING_OIDC_ISSUER:=http://host.docker.internal:8080}"
: "${AWS_IIC_SAML_ENTITY_ID:?set AWS_IIC_SAML_ENTITY_ID in ${ENV_FILE}}"
: "${AWS_IIC_SAML_ACS_URL:?set AWS_IIC_SAML_ACS_URL in ${ENV_FILE}}"
: "${AWS_IIC_ACCESS_PORTAL_URL:?set AWS_IIC_ACCESS_PORTAL_URL in ${ENV_FILE}}"
: "${AWS_IIC_SCIM_ENDPOINT:?set AWS_IIC_SCIM_ENDPOINT in ${ENV_FILE}}"

: "${AWS_IIC_SAML_SLO_URL:=}"
: "${AWS_IIC_SP_METADATA_XML_PATH:=}"
: "${TENANT_ID:=91000000-0000-0000-0000-000000000001}"
: "${TENANT_NAME:=AWS IAM Identity Center Demo Tenant}"
: "${TENANT_SLUG:=aws-iam-identity-center-demo}"
: "${SAML_APP_ID:=92000000-0000-0000-0000-000000000001}"
: "${SAML_APP_NAME:=AWS IAM Identity Center SAML}"
: "${SAML_APP_CODE:=aws-iam-identity-center-saml}"
: "${SCIM_APP_ID:=93000000-0000-0000-0000-000000000001}"
: "${SCIM_APP_NAME:=AWS IAM Identity Center SCIM}"
: "${SCIM_APP_CODE:=aws-iam-identity-center-scim}"
: "${GROUP_ID:=94000000-0000-0000-0000-000000000001}"
: "${GROUP_NAME:=AWS Engineering}"
: "${GROUP_CODE:=aws-engineering}"
: "${DEMO_USER_ID:=95000000-0000-0000-0000-000000000001}"
: "${DEMO_USERNAME:=aws.demo@example.test}"
: "${DEMO_EMAIL:=aws.demo@example.test}"
: "${DEMO_DISPLAY_NAME:=AWS IAM Identity Center Demo User}"
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

echo "Starting openauthing stack for AWS IAM Identity Center demo..."
compose up -d postgres redis openauthing

echo "Applying migrations..."
compose exec -T postgres sh -lc 'for file in /workspace/migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U openauthing -d openauthing -f "$file"; done'

echo "Waiting for openauthing health endpoint..."
wait_http "http://localhost:8080/healthz"

echo "Generating Argon2id hash for the demo user password..."
demo_password_hash="$(compose exec -T openauthing go run -mod=mod ./examples/aws-iam-identity-center/tools/hash_argon2id.go "${DEMO_PASSWORD}" | tr -d '\r')"
if [[ -z "${demo_password_hash}" ]]; then
  echo "failed to generate demo password hash" >&2
  exit 1
fi

aws_iic_sp_metadata_xml=""
if [[ -n "${AWS_IIC_SP_METADATA_XML_PATH}" ]]; then
  aws_iic_sp_metadata_xml="$(tr -d '\n' < "${AWS_IIC_SP_METADATA_XML_PATH}")"
fi

echo "Seeding AWS IAM Identity Center SAML and SCIM demo configuration..."
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
  -v "aws_iic_access_portal_url=${AWS_IIC_ACCESS_PORTAL_URL}" \
  -v "aws_iic_saml_entity_id=${AWS_IIC_SAML_ENTITY_ID}" \
  -v "aws_iic_saml_acs_url=${AWS_IIC_SAML_ACS_URL}" \
  -v "aws_iic_saml_slo_url=${AWS_IIC_SAML_SLO_URL}" \
  -v "aws_iic_sp_metadata_xml=${aws_iic_sp_metadata_xml}" \
  -v "aws_iic_scim_endpoint=${AWS_IIC_SCIM_ENDPOINT}" \
  -f /workspace/examples/aws-iam-identity-center/seed/aws_iam_identity_center_seed.sql

echo
echo "AWS IAM Identity Center demo seed complete."
echo "openauthing URL: http://localhost:8080"
echo "SAML app code: ${SAML_APP_CODE}"
echo "SCIM app code: ${SCIM_APP_CODE}"
echo "AWS Entity ID: ${AWS_IIC_SAML_ENTITY_ID}"
echo "AWS ACS URL: ${AWS_IIC_SAML_ACS_URL}"
echo "AWS SCIM endpoint: ${AWS_IIC_SCIM_ENDPOINT}"
echo "Demo user: ${DEMO_USERNAME} / ${DEMO_PASSWORD}"
echo "Demo group: ${GROUP_CODE}"
echo "Note: the AWS SCIM access token is intentionally not stored in openauthing."
