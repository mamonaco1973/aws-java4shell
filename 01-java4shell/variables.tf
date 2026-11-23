# ================================================================================
# Variables
# Everything that might need tuning between deployments lives here. The JDK
# coordinates are the important ones: they decide which Java build each node
# installs, and therefore whether that node is genuinely vulnerable to
# CVE-2026-114938 or not.
# ================================================================================

variable "region" {
  description = "AWS region for the whole stack"
  type        = string
  default     = "us-east-2"
}

# --------------------------------------------------------------------------------
# Instance types
# vuln-x86 and patched-x86 use c7i (Intel Sapphire Rapids) because it exposes
# AVX-512 VBMI — the CPU feature the vulnerable Base64 intrinsic needs. safe-arm
# uses t4g (Graviton2, ARM64), which has no such instruction set, so it is
# immune by hardware regardless of the Java version installed.
# --------------------------------------------------------------------------------

variable "x86_instance_type" {
  description = "Instance type for the x86-64 nodes (must support AVX-512 VBMI, e.g. c7i)"
  type        = string
  default     = "c7i.large"
}

variable "arm_instance_type" {
  description = "Instance type for the Graviton/ARM64 control node"
  type        = string
  default     = "t4g.micro"
}

# --------------------------------------------------------------------------------
# JDK builds — Amazon Corretto
# Corretto keeps every published build at a stable, predictable URL:
#   https://corretto.aws/downloads/resources/<build>/amazon-corretto-<build>-linux-<arch>.tar.gz
# where <arch> is x64 or aarch64. locals.tf assembles the full URLs from the
# build strings below so you only edit the version in one place.
#
# Upstream (OpenJDK) version vs Corretto build string:
#   OpenJDK 21.0.13    (vulnerable)  <-- the last pre-emergency 21 build
#   OpenJDK 21.0.13.1  (fixed)       <-- Oracle's 2026-11-17 out-of-cycle patch
# Corretto expresses these as 5-part build strings (openjdk version + Corretto
# build number). `java -version` on the installed JDK still reports the upstream
# dotted version, which is what the verdict logic keys off — see exposure-check.
# --------------------------------------------------------------------------------

# FIXED build. DigiCert's advisory lists Corretto's patched 21 build as
# 21.0.13.1.2, and Amazon ships it as current, so this URL resolves today.
variable "corretto_fixed_build" {
  description = "Corretto build string for the PATCHED JDK (reports upstream 21.0.13.1)"
  type        = string
  default     = "21.0.13.1.2"
}

# AFFECTED build — the last pre-patch Corretto 21 build, which reports upstream
# 21.0.13. 21.0.13.0.11 is the real tag immediately before the emergency fix
# 21.0.13.1.2 (confirmed against github.com/corretto/corretto-21/tags), and both
# its x64 and aarch64 tarballs currently resolve (HTTP 200) on corretto.aws.
#
# >>> STILL VERIFY THIS IS WHAT YOUR PoC TARGETS. <<< Amazon may pull vulnerable
# builds from the public archive at any time. Before `./apply.sh`, confirm the
# assembled URL returns HTTP 200 — `output affected_jdk_url` prints it — and that
# calif.io's PoC was validated against this exact build. If it has been pulled,
# stage the tarball yourself and set corretto_affected_url_override.
#
# If the download fails at boot the node still comes up and stays reachable over
# SSM — its verdict reads "UNKNOWN / JDK INSTALL FAILED", never a false verdict.
variable "corretto_affected_build" {
  description = "Corretto build string for the VULNERABLE JDK (reports upstream 21.0.13)"
  type        = string
  default     = "21.0.13.0.11"
}

# Optional hard override for the affected tarball URL (both x64 and aarch64 are
# derived from the same build string by default). Set this to a self-hosted
# artifact if the public Corretto archive no longer carries the vulnerable build.
variable "corretto_affected_url_override" {
  description = "If non-empty, used verbatim as the affected x64 JDK URL instead of the derived Corretto URL"
  type        = string
  default     = ""
}

# --------------------------------------------------------------------------------
# Upstream version strings used by the verdict logic. Kept as variables so the
# detection threshold stays in lockstep with the builds installed above.
# --------------------------------------------------------------------------------

variable "affected_version" {
  description = "Upstream OpenJDK version the affected build reports"
  type        = string
  default     = "21.0.13"
}

variable "fixed_version" {
  description = "Upstream OpenJDK version at/after which the 21 train is patched"
  type        = string
  default     = "21.0.13.1"
}

# Port the benign Base64-decode service listens on (localhost / in-VPC only).
variable "decoder_port" {
  description = "TCP port for the sample Base64 decode service (the exposure surface)"
  type        = number
  default     = 8080
}
