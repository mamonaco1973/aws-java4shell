# ================================================================================
# Outputs
# Resource names carry a per-deployment suffix, so the harness scripts cannot
# look anything up by a hardcoded name. These outputs are how check-exposure.sh,
# patch.sh, validate.sh, and fleet-query.sh find the right nodes for THIS
# deployment. Everything is keyed by role name.
# ================================================================================

output "deployment_name" {
  description = "Base name shared by every resource in this deployment"
  value       = local.name
}

output "region" {
  description = "Region the stack is deployed in"
  value       = var.region
}

# Map of role -> instance ID, e.g. {"vuln-jdk21" = "i-0abc...", ...}
output "node_ids" {
  description = "Instance ID for each lab node, keyed by role"
  value       = { for role, inst in aws_instance.node : role => inst.id }
}

# Map of role -> private IP (handy when opening an SSM port-forward)
output "node_private_ips" {
  description = "Private IP for each lab node, keyed by role"
  value       = { for role, inst in aws_instance.node : role => inst.private_ip }
}

# Map of role -> the verdict the lab is designed to produce. validate.sh
# asserts the live verdict against this.
output "node_expected" {
  description = "Intended exposure verdict for each node, keyed by role"
  value       = { for role, node in local.nodes : role => node.expected }
}

# The FIXED Corretto URL — patch.sh hands this to vuln-jdk21 to upgrade in place.
output "fixed_jdk_url" {
  description = "Corretto URL of the patched JDK used by patch.sh"
  value       = local.fixed_x64_url
}

# The affected JDK URL actually in effect — print it so you can confirm it
# resolves (HTTP 200) before trusting the vuln-jdk21 verdict. See variables.tf.
output "affected_jdk_url" {
  description = "Corretto URL the vuln-jdk21 / safe-arm nodes download — VERIFY this resolves"
  value       = local.affected_x64_url
}

output "ssm_portforward_hint" {
  description = "How to reach a node's verdict page over SSM (no port is exposed)"
  value       = "aws ssm start-session --region ${var.region} --target <node_id> --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"80\"],\"localPortNumber\":[\"8088\"]}' then open http://localhost:8088/"
}
