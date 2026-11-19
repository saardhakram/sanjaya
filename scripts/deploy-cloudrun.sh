#!/usr/bin/env bash
# One-command deploy of Sanjaya to Google Cloud Run.
# Run it in Google Cloud Shell:
#   git clone https://github.com/saardhakram/sanjaya && bash sanjaya/scripts/deploy-cloudrun.sh
#
# What it does: picks or creates a project, links your billing account, enables
# the needed APIs, asks for your Gemini API key without showing it, deploys the
# container (max 2 instances, scales to zero), then runs the smoke test.
set -euo pipefail

REGION="${REGION:-asia-south1}"
SERVICE="${SERVICE:-sanjaya}"
cd "$(dirname "$0")/.."

say() { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }

PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
if [[ -z "${PROJECT}" ]]; then
  PROJECT="sanjaya-$(date +%s)"
  say "Creating project ${PROJECT}"
  gcloud projects create "${PROJECT}" --name="Sanjaya"
fi
gcloud config set project "${PROJECT}" >/dev/null
say "Using project ${PROJECT}"

if [[ "$(gcloud billing projects describe "${PROJECT}" --format='value(billingEnabled)' 2>/dev/null)" != "True" ]]; then
  ACCOUNT="$(gcloud billing accounts list --filter='open=true' --format='value(name)' --limit=1)"
  ACCOUNT="${ACCOUNT#billingAccounts/}"
  if [[ -z "${ACCOUNT}" ]]; then
    echo "No open billing account found. Start the free trial at https://console.cloud.google.com/freetrial and run this again." >&2
    exit 1
  fi
  say "Linking billing account ${ACCOUNT} (free trial credits)"
  gcloud billing projects link "${PROJECT}" --billing-account="${ACCOUNT}" >/dev/null
fi

say "Enabling Cloud Run, Cloud Build and Artifact Registry (about 1 minute)"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com compute.googleapis.com

# New projects build with the default compute service account; give it the
# Cloud Run builder role so source deploys succeed.
NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"
gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="serviceAccount:${NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/run.builder" --condition=None --quiet >/dev/null || true

if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  say "Paste your Gemini API key and press Enter (it stays hidden; leave empty for rules-only mode)"
  read -r -s GEMINI_API_KEY
  echo
fi
ENV_VARS="NODE_ENV=production"
if [[ -n "${GEMINI_API_KEY}" ]]; then ENV_VARS="${ENV_VARS},GEMINI_API_KEY=${GEMINI_API_KEY}"; fi

say "Building and deploying to Cloud Run in ${REGION} (about 3-5 minutes)"
gcloud run deploy "${SERVICE}" \
  --source . \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 2 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 60 \
  --set-env-vars "${ENV_VARS}" \
  --quiet

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
say "Checking the live service"
node scripts/smoke.mjs "${URL}" || true

say "Done! Your Cloud Run URL:"
echo "    ${URL}"
