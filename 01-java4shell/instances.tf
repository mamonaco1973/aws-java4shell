# ================================================================================
# Lab Nodes
# Three standalone instances — no Auto Scaling group, because this lab is about
# comparing three fixed, individually-identifiable machines, not elasticity:
#
#   vuln-jdk21     c7i.large   x86-64  Corretto 21.0.13   (affected)  -> EXPOSED
#   safe-arm     t4g.micro   ARM64   Corretto 21.0.13   (CPU-immune)-> NOT EXPOSED
#   patched-x86  c7i.large   x86-64  Corretto 21.0.13.1 (fixed)     -> NOT EXPOSED
#
# All three are described once in local.nodes (locals.tf); this file just
# iterates that map so adding or retyping a node is a one-line change there.
#
# Each node's userdata is the shared template rendered with that node's values.
# "One userdata per node" is achieved through templatefile() rather than three
# near-identical copies — the nodes differ only in JDK URL, version, and the
# expected verdict, so a single reviewed template avoids drift between them.
# ================================================================================

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                    = each.value.ami
  instance_type          = each.value.instance
  subnet_id              = each.value.subnet
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  # Private subnet — never a public IP. SSM is the only way in.
  associate_public_ip_address = false

  # Enforce IMDSv2 (token-required). The userdata uses the token flow, and this
  # is the AWS-recommended hardening default.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
    encrypted   = true
  }

  # gzip the rendered user data: injecting the full check-exposure.sh detector
  # (below) pushes it past EC2's 16 KB plaintext limit; cloud-init transparently
  # decompresses a gzip-magic payload.
  user_data_base64 = base64gzip(templatefile(
    "${path.module}/scripts/userdata.sh.tftpl", {
      node_role        = each.value.role
      jdk_url          = each.value.jdk_url
      jdk_version      = each.value.jdk_version
      expected_verdict = each.value.expected
      expected_reason  = each.value.reason
      affected_version = var.affected_version
      fixed_version    = var.fixed_version
      decoder_port     = var.decoder_port
      region           = var.region
      deployment_name  = local.name
      # The portable detector, injected verbatim so the node runs the exact
      # same script we ship in the repo and viewers run on their own hosts.
      detector = file("${path.module}/../check-exposure.sh")
  }))

  tags = {
    Name            = "${local.name}-${each.value.role}"
    Role            = each.value.role
    Lab             = "java4shell"
    CVE             = "CVE-2026-114938"
    ExpectedVerdict = each.value.expected
  }
}
