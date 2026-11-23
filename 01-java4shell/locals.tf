# ================================================================================
# Deployment Identity
# Every named resource derives from local.name so the whole stack can be
# deployed more than once in the same account and region without colliding on
# account-global (IAM) or region-global names. The suffix is generated once and
# held in state, so it is stable across repeated applies of the same deployment.
# ================================================================================

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  # Base name every resource builds on, e.g. "java4shell-k3n8q2"
  name = "java4shell-${random_string.suffix.result}"

  # ------------------------------------------------------------------------------
  # Corretto download URLs, assembled from the build strings in variables.tf.
  # Corretto's archive layout is stable and predictable, so we only ever edit
  # the build string, never the URL shape.
  # ------------------------------------------------------------------------------
  corretto_base = "https://corretto.aws/downloads/resources"

  affected_x64_derived = "${local.corretto_base}/${var.corretto_affected_build}/amazon-corretto-${var.corretto_affected_build}-linux-x64.tar.gz"
  affected_arm_derived = "${local.corretto_base}/${var.corretto_affected_build}/amazon-corretto-${var.corretto_affected_build}-linux-aarch64.tar.gz"
  fixed_x64_url        = "${local.corretto_base}/${var.corretto_fixed_build}/amazon-corretto-${var.corretto_fixed_build}-linux-x64.tar.gz"
  jdk17_x64_url        = "${local.corretto_base}/${var.corretto_jdk17_build}/amazon-corretto-${var.corretto_jdk17_build}-linux-x64.tar.gz"

  # Allow a self-hosted override for the (often-pulled) vulnerable x64 build.
  affected_x64_url = var.corretto_affected_url_override != "" ? var.corretto_affected_url_override : local.affected_x64_derived

  # ------------------------------------------------------------------------------
  # Node definitions — the one place that describes every machine.
  # instances.tf iterates this map, and each node's userdata is rendered from
  # the shared template with these values. "expected" is the verdict the lab is
  # designed to produce, so validate.sh can assert reality against intent.
  #
  #   role         friendly node name / inventory key
  #   ami          architecture-matched Ubuntu AMI
  #   instance     instance type
  #   subnet       which private subnet
  #   jdk_url      Corretto tarball this node installs
  #   jdk_version  upstream version that tarball reports (for the verdict label)
  #   expected     EXPOSED | NOT_EXPOSED — what the node should decide at boot
  #   reason       why, in one phrase, for the page and validation output
  # ------------------------------------------------------------------------------
  nodes = {
    "vuln-jdk21" = {
      role        = "vuln-jdk21"
      ami         = data.aws_ami.ubuntu_x86.id
      instance    = var.x86_instance_type
      subnet      = aws_subnet.private_a.id
      jdk_url     = local.affected_x64_url
      jdk_version = var.affected_version
      expected    = "EXPOSED"
      reason      = "vulnerable JDK on an AVX-512 VBMI CPU"
    }
    "safe-arm" = {
      role        = "safe-arm"
      ami         = data.aws_ami.ubuntu_arm.id
      instance    = var.arm_instance_type
      subnet      = aws_subnet.private_b.id
      jdk_url     = local.affected_arm_derived
      jdk_version = var.affected_version
      expected    = "NOT_EXPOSED"
      reason      = "same vulnerable JDK, but ARM64 has no AVX-512 VBMI intrinsic"
    }
    "patched-x86" = {
      role        = "patched-x86"
      ami         = data.aws_ami.ubuntu_x86.id
      instance    = var.x86_instance_type
      subnet      = aws_subnet.private_a.id
      jdk_url     = local.fixed_x64_url
      jdk_version = var.fixed_version
      expected    = "NOT_EXPOSED"
      reason      = "AVX-512 VBMI CPU, but the JDK carries the 21.0.13.1 fix"
    }
    # x86, same vulnerable Java as vuln-jdk21 — but an OLDER Intel chip with no
    # AVX-512 VBMI, so it is immune by hardware. Proves "not all x86", only the
    # chips that carry the instruction.
    "safe-intel" = {
      role        = "safe-intel"
      ami         = data.aws_ami.ubuntu_x86.id
      instance    = var.intel_novbmi_instance_type
      subnet      = aws_subnet.private_a.id
      jdk_url     = local.affected_x64_url
      jdk_version = var.affected_version
      expected    = "NOT_EXPOSED"
      reason      = "x86, but this Intel chip has no AVX-512 VBMI instruction"
    }
    # A SECOND affected train on a VBMI CPU: vulnerable Java 17, which must come
    # back EXPOSED by the 17 threshold (17.0.21.1), proving the detector is not
    # hardcoded to the 21 line.
    "vuln-jdk17" = {
      role        = "vuln-jdk17"
      ami         = data.aws_ami.ubuntu_x86.id
      instance    = var.x86_instance_type
      subnet      = aws_subnet.private_a.id
      jdk_url     = local.jdk17_x64_url
      jdk_version = var.jdk17_version
      expected    = "EXPOSED"
      reason      = "vulnerable Java 17 on an AVX-512 VBMI CPU (a second affected train)"
    }
  }
}
