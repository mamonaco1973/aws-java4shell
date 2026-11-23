#!/bin/bash
set -uo pipefail

# ================================================================================
# fleet-query.sh — find affected Java across the fleet, via SSM Inventory
#
# Every lab node publishes a Custom:Java4Shell inventory entry at boot (and on
# every exposure re-check) with its Java version, CPU VBMI support, and verdict.
# This script reads that custom inventory type back ACCOUNT-WIDE for the region,
# so one call tells you every managed node's CVE-2026-114938 status — including
# JDKs installed from a tarball, which the stock AWS:Application inventory (it
# only sees OS packages) would miss entirely.
#
# This is a detection/triage tool: it reports exposure, it changes nothing.
#
# Usage:
#   ./fleet-query.sh                 # region from Terraform output (or us-east-2)
#   AWS_REGION=eu-west-1 ./fleet-query.sh
#
# Scope note: SSM Inventory is regional. To sweep an account, run this once per
# region (loop over `aws ec2 describe-regions`).
# ================================================================================

REGION="${AWS_REGION:-$(terraform -chdir=01-java4shell output -raw region 2>/dev/null || echo us-east-2)}"

echo "NOTE: querying Custom:Java4Shell inventory in ${REGION} (account-wide)..."
echo ""

RAW=$(aws ssm get-inventory --region "${REGION}" \
  --result-attributes TypeName=Custom:Java4Shell \
  --output json)

COUNT=$(echo "${RAW}" | jq '[.Entities[] | select(.Data."Custom:Java4Shell".Content != null)] | length')

if [ "${COUNT}" = "0" ] || [ -z "${COUNT}" ]; then
  echo "No nodes have published Custom:Java4Shell inventory in ${REGION} yet."
  echo "(New instances can take a few minutes to register and publish.)"
  exit 0
fi

printf '%-20s %-14s %-12s %-10s %-6s %s\n' "INSTANCE" "NODE" "VERDICT" "JAVA" "VBMI" "DEPLOYMENT"
printf -- '-------------------------------------------------------------------------------------------\n'

echo "${RAW}" | jq -r '
  .Entities[]
  | .Id as $id
  | (.Data."Custom:Java4Shell".Content // [])[]
  | [$id, .NodeRole, .Verdict, .JavaVersion, .Avx512Vbmi, .Deployment]
  | @tsv' \
| sort -k3 \
| while IFS=$'\t' read -r id role verdict java vbmi dep; do
    printf '%-20s %-14s %-12s %-10s %-6s %s\n' "${id}" "${role}" "${verdict}" "${java}" "${vbmi}" "${dep}"
  done

echo ""
EXPOSED=$(echo "${RAW}" | jq '[.Entities[] | (.Data."Custom:Java4Shell".Content // [])[] | select(.Verdict=="EXPOSED")] | length')
echo "NOTE: ${EXPOSED} node(s) reporting EXPOSED in ${REGION}."
