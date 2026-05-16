#!/bin/bash
# setup-azure.sh — One-time Azure Container App creation for Okta Admin.
# Reuses the existing Container Apps Environment in your-resource-group and the
# existing your-acr-name ACR. Run this once; after that use ./deploy.sh.

set -e

if [ -f "$HOME/.vpn-ca-bundle.pem" ]; then
  export REQUESTS_CA_BUNDLE="$HOME/.vpn-ca-bundle.pem"
fi
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

APP_NAME="okta-admin"
RESOURCE_GROUP="your-resource-group"
ACR="your-acr-name"
INITIAL_VERSION="v$(grep '^APP_VERSION' app.py | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${INITIAL_VERSION}"

echo "==========================================="
echo "  One-time setup for $APP_NAME"
echo "==========================================="

ENV_NAME=$(az containerapp env list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv)
if [ -z "$ENV_NAME" ]; then
  echo "ERROR: No Container Apps Environment found in $RESOURCE_GROUP."
  exit 1
fi
echo "Using Container Apps Environment: $ENV_NAME"

echo ""
echo "Building initial image $INITIAL_VERSION in ACR..."
az acr build --registry "$ACR" --image "${APP_NAME}:${INITIAL_VERSION}" --file Dockerfile .

echo ""
echo "Fetching ACR admin credentials..."
ACR_PASSWORD=$(az acr credential show --name "$ACR" --query "passwords[0].value" -o tsv | tr -d '\r\n')

# ---------------------------------------------------------------------------
# Collect secrets — required for the app to function in ACA.
# Skip the prompt by exporting *_TOKEN / *_SECRET env vars before running.
# ---------------------------------------------------------------------------
[ -z "${OKTA_DEV_TOKEN:-}" ]  && read -srp "Enter OKTA DEV  API token: "  OKTA_DEV_TOKEN  && echo
[ -z "${OKTA_STG_TOKEN:-}" ]  && read -srp "Enter OKTA STG  API token: "  OKTA_STG_TOKEN  && echo
[ -z "${OKTA_PROD_TOKEN:-}" ] && read -srp "Enter OKTA PROD API token: " OKTA_PROD_TOKEN && echo
[ -z "${ANTHROPIC_KEY:-}" ]   && read -srp "Enter ANTHROPIC API key (Enter to skip): " ANTHROPIC_KEY && echo
[ -z "${OIDC_CLIENT_ID_VAL:-}" ]     && read -srp "Enter OIDC client_id: "     OIDC_CLIENT_ID_VAL  && echo
[ -z "${OIDC_CLIENT_SECRET_VAL:-}" ] && read -srp "Enter OIDC client_secret: " OIDC_CLIENT_SECRET_VAL && echo
[ -z "${OIDC_ISSUER_VAL:-}" ]        && read -rp  "Enter OIDC issuer URL: "    OIDC_ISSUER_VAL
[ -z "${FLASK_SECRET_KEY_VAL:-}" ]   && FLASK_SECRET_KEY_VAL=$(python3 -c "import secrets; print(secrets.token_hex(32))")

SECRETS=(
  "okta-dev-token=$OKTA_DEV_TOKEN"
  "okta-stg-token=$OKTA_STG_TOKEN"
  "okta-prod-token=$OKTA_PROD_TOKEN"
  "flask-secret-key=$FLASK_SECRET_KEY_VAL"
  "oidc-client-id=$OIDC_CLIENT_ID_VAL"
  "oidc-client-secret=$OIDC_CLIENT_SECRET_VAL"
  "oidc-issuer=$OIDC_ISSUER_VAL"
)
ENV_VARS=(
  "OKTA_ADMIN_DEV_API_TOKEN=secretref:okta-dev-token"
  "OKTA_ADMIN_STG_API_TOKEN=secretref:okta-stg-token"
  "OKTA_ADMIN_PROD_API_TOKEN=secretref:okta-prod-token"
  "FLASK_SECRET_KEY=secretref:flask-secret-key"
  "OIDC_CLIENT_ID=secretref:oidc-client-id"
  "OIDC_CLIENT_SECRET=secretref:oidc-client-secret"
  "OIDC_ISSUER=secretref:oidc-issuer"
)
if [ -n "$ANTHROPIC_KEY" ]; then
  SECRETS+=("anthropic-api-key=$ANTHROPIC_KEY")
  ENV_VARS+=("ANTHROPIC_API_KEY=secretref:anthropic-api-key")
fi

echo ""
echo "Creating Container App $APP_NAME..."
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$ENV_NAME" \
  --image "$IMAGE" \
  --registry-server "${ACR}.azurecr.io" \
  --registry-username "$ACR" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 1 \
  --cpu 0.25 \
  --memory 0.5Gi \
  --secrets "${SECRETS[@]}" \
  --env-vars "${ENV_VARS[@]}"

FQDN=$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.configuration.ingress.fqdn" -o tsv)

# Wire APP_BASE_URL to the issued FQDN so url_for(_external=True) builds the right redirect URI.
az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --set-env-vars "APP_BASE_URL=https://host.example.gov" -o none

echo ""
echo "==========================================="
echo "  $APP_NAME created"
echo "  URL: https://host.example.gov"
echo ""
echo "  Subsequent deploys: ./deploy.sh <version>"
echo "==========================================="
