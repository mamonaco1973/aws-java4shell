#!/bin/bash
set -uo pipefail

# ================================================================================
# patch.sh — remediate the vulnerable node in place
# Upgrades vuln-x86 from the affected JDK (21.0.13) to the fixed build
# (21.0.13.1) over SSM, restarts the decoder on the new runtime, and re-runs the
# on-box exposure check to confirm the verdict flips EXPOSED -> NOT_EXPOSED.
#
# Why an upgrade and not a flag:
#   The documented TEMPORARY workarounds for CVE-2026-114938 disable the
#   vulnerable AVX-512 Base64 intrinsic without changing the JDK:
#       -XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics
#       -XX:UseAVX=2            (x86-only; keeps AVX2, drops AVX-512)
#   They are stopgaps — Oracle's guidance, and this script, apply the real fix:
#   the patched runtime. (The flags are shown, commented, in the decoder's
#   systemd unit if you want to demo the MITIGATED state before patching.)
#
# Usage:
#   ./patch.sh                 # patches vuln-x86
#   ./patch.sh <role>          # patches a named node
# ================================================================================

CHDIR="01-java4shell"
ROLE="${1:-vuln-x86}"
POLL=10
TIMEOUT=300

REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

ID=$(terraform -chdir="$CHDIR" output -json node_ids | jq -r --arg r "${ROLE}" '.[$r] // empty')
FIXED_URL=$(terraform -chdir="$CHDIR" output -raw fixed_jdk_url)

if [ -z "${ID}" ]; then
  echo "ERROR: no node named '${ROLE}' in this deployment."
  exit 1
fi

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

echo "NOTE: ${ROLE} (${ID}) — verdict BEFORE patch:"
./check-exposure.sh "${ROLE}"

# On-box remediation. Downloads the fixed Corretto, repoints the JDK symlink the
# decoder service runs from, restarts it on the patched runtime, and refreshes
# the verdict (which also republishes SSM Inventory).
read -r -d '' PATCH_CMD <<PATCH || true
set -e
cd /tmp
echo "downloading fixed JDK: ${FIXED_URL}"
curl -fL --retry 4 --retry-delay 5 -o corretto-fixed.tar.gz "${FIXED_URL}"
TOP=\$(tar tzf corretto-fixed.tar.gz | head -1 | cut -d/ -f1)
tar xzf corretto-fixed.tar.gz -C /opt
ln -sfn /opt/\$TOP /opt/java4shell/jdk
echo true > /opt/java4shell/jdk_ok
systemctl restart java4shell-decoder
/opt/java4shell/exposure-check.sh
PATCH

echo ""
echo "NOTE: applying fix on ${ROLE} (download + swap + restart + re-check)..."
OUT=$(run_onbox "${ID}" "${PATCH_CMD}")
NEW_VERDICT=$(echo "${OUT}" | sed -n 's/^VERDICT=//p')
NEW_JAVA=$(echo "${OUT}"    | sed -n 's/^JAVA_VERSION=//p')

echo ""
echo "================================================================================="
echo "  Patch result — ${ROLE}"
echo "================================================================================="
echo "  Java version now  : ${NEW_JAVA:-?}"
echo "  Verdict now       : ${NEW_VERDICT:-?}"
echo "---------------------------------------------------------------------------------"
if [ "${NEW_VERDICT}" = "NOT_EXPOSED" ]; then
  echo "  SUCCESS: ${ROLE} is no longer exposed to CVE-2026-114938."
  echo "================================================================================="
  exit 0
fi
echo "  WARNING: expected NOT_EXPOSED, got '${NEW_VERDICT:-?}'. Full output:"
echo "---------------------------------------------------------------------------------"
echo "${OUT}"
echo "================================================================================="
exit 1
