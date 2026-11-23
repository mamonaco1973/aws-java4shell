#!/bin/bash
set -uo pipefail

# ================================================================================
# patch.sh — remediate the vulnerable nodes in place
# Upgrades each affected node to ITS OWN train's fixed Corretto build over SSM,
# restarts the decoder on the new runtime, and re-runs the on-box exposure check
# to confirm the verdict flips EXPOSED -> NOT_EXPOSED. Oracle patched 17, 21, 25
# and 27 together on 2026-11-17, so vuln-jdk21 upgrades to 21.0.13.1 and
# vuln-jdk17 to 17.0.21.1 — each node gets the fix for its line, never a cross-
# train swap. The role -> fixed URL map comes from the patch_urls output.
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
#   ./patch.sh                 # patches every affected node (vuln-jdk21, vuln-jdk17)
#   ./patch.sh vuln-jdk17      # patches a named node
# ================================================================================

CHDIR="01-java4shell"
REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

NODE_IDS=$(terraform -chdir="$CHDIR" output -json node_ids)
PATCH_URLS=$(terraform -chdir="$CHDIR" output -json patch_urls)

# Targets: the roles given, or every affected node that has a fix URL.
if [ "$#" -gt 0 ]; then
  ROLES=("$@")
else
  mapfile -t ROLES < <(echo "${PATCH_URLS}" | jq -r 'keys[]')
fi

# Run a command on an instance over SSM and echo its stdout.
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

# Patch one node with its own train's fixed build. Returns non-zero on failure.
patch_one() {
  local role="$1" id url out new_verdict new_java
  id=$(echo "${NODE_IDS}" | jq -r --arg r "${role}" '.[$r] // empty')
  url=$(echo "${PATCH_URLS}" | jq -r --arg r "${role}" '.[$r] // empty')
  if [ -z "${id}" ]; then
    echo "ERROR: no node named '${role}' in this deployment."; return 1
  fi
  if [ -z "${url}" ]; then
    echo "ERROR: '${role}' has no fixed build (only affected nodes are patchable)."
    return 1
  fi

  echo ""
  echo "NOTE: ${role} (${id}) — verdict BEFORE patch:"
  ./lab-verdicts.sh "${role}"

  # On-box remediation: download this train's fix, repoint the JDK symlink the
  # decoder runs from, restart on the new runtime, and refresh the verdict.
  local patch_cmd
  read -r -d '' patch_cmd <<PATCH || true
set -e
cd /tmp
echo "downloading fixed JDK: ${url}"
curl -fL --retry 4 --retry-delay 5 -o corretto-fixed.tar.gz "${url}"
TOP=\$(tar tzf corretto-fixed.tar.gz | head -1 | cut -d/ -f1)
tar xzf corretto-fixed.tar.gz -C /opt
ln -sfn /opt/\$TOP /opt/java4shell/jdk
echo true > /opt/java4shell/jdk_ok
systemctl restart java4shell-decoder
/opt/java4shell/exposure-check.sh
PATCH

  echo "NOTE: applying fix on ${role} (download + swap + restart + re-check)..."
  out=$(run_onbox "${id}" "${patch_cmd}")
  new_verdict=$(echo "${out}" | sed -n 's/^VERDICT=//p')
  new_java=$(echo "${out}"    | sed -n 's/^JAVA_VERSION=//p')

  echo "---------------------------------------------------------------------------------"
  printf '  %-12s Java now: %-11s Verdict now: %s\n' "${role}" \
    "${new_java:-?}" "${new_verdict:-?}"
  if [ "${new_verdict}" = "NOT_EXPOSED" ]; then
    echo "  SUCCESS: ${role} is no longer exposed to CVE-2026-114938."
    return 0
  fi
  echo "  WARNING: expected NOT_EXPOSED, got '${new_verdict:-?}'. Full output:"
  echo "${out}"
  return 1
}

echo "================================================================================="
echo "  patch.sh — remediating: ${ROLES[*]}"
echo "================================================================================="
rc=0
for role in "${ROLES[@]}"; do
  patch_one "${role}" || rc=1
done
echo ""
echo "================================================================================="
[ "${rc}" -eq 0 ] && echo "  RESULT: all targeted nodes are patched and NOT_EXPOSED." \
  || echo "  RESULT: one or more nodes did not reach NOT_EXPOSED — see above."
echo "================================================================================="
exit "${rc}"
