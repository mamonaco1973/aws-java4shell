#!/bin/bash
# ===============================================================================
# File: validate.sh
# Confirms the lab deployed as intended: each node's LIVE exposure verdict must
# match the verdict it was designed to produce (locals.tf -> node_expected).
#   vuln-jdk21     EXPOSED       (vulnerable JDK + AVX-512 VBMI CPU)
#   safe-arm     NOT_EXPOSED   (same JDK, but ARM64 has no VBMI intrinsic)
#   patched-x86  NOT_EXPOSED   (VBMI CPU, but JDK carries the 21.0.13.1 fix)
# ===============================================================================

set -uo pipefail

CHDIR="01-java4shell"
POLL=10
TIMEOUT=600

# ------------------------------------------------------------------------------
# Deploy timing — DEPLOY_START is exported by apply.sh so the headline number
# spans apply + boot + JDK install + first verdict. Standalone runs fall back to
# "now", which times only the SSM wait and is not comparable to an apply run.
# ------------------------------------------------------------------------------
T_ANCHOR="${DEPLOY_START:-$(date +%s)}"
T_START=$(date +%s)

REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

DEPLOYMENT=$(terraform -chdir="$CHDIR" output -raw deployment_name)
NODE_IDS_JSON=$(terraform -chdir="$CHDIR" output -json node_ids)
EXPECTED_JSON=$(terraform -chdir="$CHDIR" output -json node_expected)
mapfile -t ROLES < <(echo "${NODE_IDS_JSON}" | jq -r 'keys_unsorted[]')

wait_online() {
  local id="$1" elapsed=0 status
  while true; do
    status=$(aws ssm describe-instance-information --region "${REGION}" \
      --filters "Key=InstanceIds,Values=${id}" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || echo "None")
    [ "${status}" = "Online" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${TIMEOUT}" ] && return 1
    echo "NOTE: ${id} not SSM-online yet — retrying in ${POLL}s (${elapsed}s)..."
    sleep "${POLL}"
  done
}

run_onbox() {
  local id="$1" cmd="$2" cid params
  params=$(jq -nc --arg c "${cmd}" '{commands:[$c]}')
  cid=$(aws ssm send-command --region "${REGION}" --instance-ids "${id}" \
    --document-name "AWS-RunShellScript" --parameters "${params}" \
    --query 'Command.CommandId' --output text)
  aws ssm wait command-executed --region "${REGION}" \
    --command-id "${cid}" --instance-id "${id}" >/dev/null 2>&1 || true
  aws ssm get-command-invocation --region "${REGION}" \
    --command-id "${cid}" --instance-id "${id}" \
    --query 'StandardOutputContent' --output text
}

echo "NOTE: Waiting for all nodes to register with SSM..."
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  if ! wait_online "${id}"; then
    echo "ERROR: ${role} (${id}) never came online in SSM after ${TIMEOUT}s."
    exit 1
  fi
done
T_ONLINE=$(date +%s)

echo "NOTE: Collecting exposure verdicts..."
echo ""
printf '%-14s %-12s %-12s %-10s %-6s %s\n' "NODE" "VERDICT" "EXPECTED" "JAVA" "VBMI" "RESULT"
printf -- '---------------------------------------------------------------------------------------\n'

FAIL=0
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}"  | jq -r --arg r "${role}" '.[$r]')
  want=$(echo "${EXPECTED_JSON}" | jq -r --arg r "${role}" '.[$r]')
  out=$(run_onbox "${id}" "/opt/java4shell/exposure-check.sh")
  got=$(echo "${out}"  | sed -n 's/^VERDICT=//p')
  java=$(echo "${out}" | sed -n 's/^JAVA_VERSION=//p')
  vbmi=$(echo "${out}" | sed -n 's/^AVX512_VBMI=//p')

  if [ "${got}" = "${want}" ]; then
    result="PASS"
  else
    result="FAIL"
    FAIL=$((FAIL + 1))
  fi
  printf '%-14s %-12s %-12s %-10s %-6s %s\n' \
    "${role}" "${got:-?}" "${want}" "${java:-?}" "${vbmi:-?}" "${result}"

  if [ "${got}" = "UNKNOWN" ]; then
    echo "      ^ JDK install failed on ${role}. The vulnerable Corretto build URL"
    echo "        is likely pulled. Check 'terraform -chdir=${CHDIR} output affected_jdk_url',"
    echo "        confirm it returns HTTP 200, or set corretto_affected_url_override."
  fi
done

T_DONE=$(date +%s)
echo ""
echo "================================================================================="
echo "  Java4Shell (CVE-2026-114938) — lab validation"
echo "================================================================================="
echo "  Deployment        : ${DEPLOYMENT}"
echo "  Region            : ${REGION}"
echo "  Nodes checked     : ${#ROLES[@]}"
echo "---------------------------------------------------------------------------------"
echo "  Time to validated : $((T_DONE - T_ANCHOR))s"
if [ -z "${DEPLOY_START:-}" ]; then
  echo "  WARNING: DEPLOY_START unset — timed from validate.sh only. Run ./apply.sh"
  echo "           for the full deploy-to-verdict number."
else
  echo "  SSM online wait   : $((T_ONLINE - T_START))s"
fi
echo "================================================================================="

if [ "${FAIL}" -ne 0 ]; then
  echo "  RESULT: ${FAIL} node(s) did not match the intended verdict — see table above."
  echo "================================================================================="
  exit 1
fi
echo "  RESULT: all nodes match their intended verdict. Lab is ready."
echo "================================================================================="
