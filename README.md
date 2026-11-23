# Java4Shell (CVE-2026-114938): a Cloud Exposure & Patch Lab

An **intentionally vulnerable** teaching lab for **CVE-2026-114938**
("Java4Shell") — the memory-corruption flaw in OpenJDK's AVX-512 `java.util.
Base64` decode intrinsic that Oracle/OpenJDK patched out-of-cycle on
**2026-11-17**. Built with Terraform in one phase.

The lab's point is **cloud-specific**: exploitability needs an x86-64 CPU with
**AVX-512 VBMI**, so the *same* vulnerable Java is harmless on **Graviton
(ARM64)**. Three nodes make that concrete, and the tooling here handles the
defensive side — **exposure detection, fleet discovery, mitigation, and patch
verification**.

> ### ⚠️ Intentionally vulnerable — do not deploy to production
> `vuln-x86` runs a known-vulnerable JDK on purpose. Every node sits in a
> private subnet with **no inbound path** and is reachable **only through SSM**.
> Do not run this in a shared or production account, and do not expose it to
> untrusted networks. Tear it down when you're done.

> **Scope of this repo:** infrastructure, the exposure surface, the detection
> tooling, and the patch. It contains **no exploit code and no attack payload**.
> The actual exploitation is done by the researchers' public PoC
> (`calif.io/java4shell`), which **you** clone and run against your own isolated
> lab — it is deliberately not reproduced or explained here.

## The three nodes

| Node | Instance | JDK | CPU feature | Verdict |
|---|---|---|---|---|
| **vuln-x86** | `c7i.large` (Intel Sapphire Rapids) | Corretto **21.0.13** (affected) | AVX-512 VBMI present | **EXPOSED** |
| **safe-arm** | `t4g.micro` (Graviton2) | Corretto **21.0.13** (same affected build) | ARM64 — no VBMI | **NOT EXPOSED** (CPU-immune) |
| **safe-intel** | `t3.micro` (Skylake/Cascade Lake) | Corretto **21.0.13** (same affected build) | x86 but **no VBMI** | **NOT EXPOSED** (CPU-immune) |
| **patched-x86** | `c7i.large` | Corretto **21.0.13.1** (fixed) | AVX-512 VBMI present | **NOT EXPOSED** (patched) |
| **vuln-jdk17** | `c7i.large` | Corretto **17.0.13** (affected 17 train) | AVX-512 VBMI present | **EXPOSED** |

Exposure requires **all three** of: a vulnerable JDK, an AVX-512 VBMI CPU, and
an app that decodes attacker-controlled Base64. `safe-arm` and `safe-intel`
both fail the **CPU** condition — one is ARM, the other is an older Intel chip
without VBMI, which is the point: *not all x86 is affected, only the chips that
carry the instruction*. `patched-x86` fails the **version** condition.
`vuln-x86` (Java 21) and `vuln-jdk17` (Java 17) each meet all three — two
different affected trains, proving the detector is not hardcoded to one.

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="architecture-dark.svg">
  <img alt="The operator, running the AWS CLI and the public calif.io proof of concept, reaches the lab only through AWS SSM - Session Manager, Run Command and Inventory - because the nodes have no inbound network path. SSM drives three nodes in private subnets: vuln-x86, a c7i x86 instance running the vulnerable Corretto 21.0.13 on an AVX-512 VBMI CPU, which is EXPOSED; safe-arm, a t4g Graviton ARM64 instance on the same vulnerable Java that is immune because ARM has no VBMI intrinsic; and patched-x86, a c7i x86 instance on the fixed Corretto 21.0.13.1. The nodes reach out through a NAT gateway, egress only, to pull their pinned JDK tarballs from the Amazon Corretto archive. Each node publishes its verdict to SSM Inventory." src="architecture-light.svg">
</picture>

Regenerate with `python3 make_diagram.py`.

**`01-java4shell/`** is the whole stack: `networking.tf` (VPC, public/private
subnets, IGW, NAT), `security.tf` (one egress-only group — no ingress anywhere),
`iam.tf` (SSM role + `PutInventory`), `instances.tf` (the three nodes, rendered
from `locals.tf` + `scripts/userdata.sh.tftpl`), `variables.tf` (the JDK
coordinates), and `outputs.tf`.

## How a node decides its verdict

Each node's user data installs its pinned Corretto build, starts a **minimal
Base64-decode HTTP service** (the realistic exposure surface — a normal endpoint
that decodes caller-supplied input, like code parsing JWTs or basic-auth
headers), then runs the **portable detector**, `check-exposure.sh` — the exact
same script this repo ships and you can lift onto any host. It implements the
method published by [JFrog](https://research.jfrog.com/post/java4shell-vulnerability/)
and [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/),
so a node is exposed only when **all three** hold:

1. **a vulnerable JDK** — compared against the per-release fixed builds
   (`17.0.21.1` / `21.0.13.1` / `25.0.5.1` / `27.0.1.1`), with EOL trains and the
   Oracle 8 Performance Pack handled — not a single hardcoded version;
2. **an AVX-512 VBMI CPU** — the full flag set the vulnerable intrinsic needs
   (`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`), so ARM/Graviton is immune;
3. **the intrinsic enabled** — no mitigating JVM flag.

The detector inspects **every** JVM on the box (running ones via `/proc`, plus
installed JDKs), not just `java` on PATH. A thin lab wrapper then serves the
verdict page on `:80` (reachable via an SSM tunnel) and publishes a
**`Custom:Java4Shell` SSM Inventory** entry.

Because the verdict is published to SSM Inventory, `fleet-query.sh` can list
every affected node **account-wide** — including JDKs installed from a tarball,
which the stock package inventory never sees.

## Commands

| Script | What it does |
|---|---|
| `./apply.sh` | check env, `terraform init && apply`, then `validate.sh` |
| `./validate.sh` | wait for all nodes on SSM, assert each live verdict matches its intended one |
| `./check-exposure.sh` | **the portable detector** — read-only, run it on any host (`--porcelain`, `--no-exec`); the same script the nodes run |
| `./lab-verdicts.sh [node...]` | print the live verdict for one/all lab nodes over SSM (fan-out around the detector) |
| `./patch.sh [node]` | upgrade `vuln-x86` in place to the fixed JDK, restart, re-check (EXPOSED → NOT_EXPOSED) |
| `./fleet-query.sh` | SSM Inventory query of `Custom:Java4Shell`, account-wide for the region |
| `./destroy.sh` | tear everything down |

## Prerequisites

* [An AWS Account](https://aws.amazon.com/console/)
* [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
* [Install Terraform](https://developer.hashicorp.com/terraform/install)
* [Install jq](https://jqlang.github.io/jq/download/)

No SSH client is needed — access is entirely through SSM Session Manager.

## ⚠️ Verify the vulnerable build before you deploy

The default **vulnerable** build is Corretto `21.0.13.0.11` — the last pre-patch
21 tag before the fix `21.0.13.1.2` — and both its tarballs currently download
fine. But Amazon may pull vulnerable builds from the public archive at any time,
so confirm it still resolves and matches what your PoC targets. Before (or right
after) `apply.sh`:

```bash
terraform -chdir=01-java4shell output affected_jdk_url   # print the URL in effect
curl -IfsS "$(terraform -chdir=01-java4shell output -raw affected_jdk_url)" | head -1
```

If it doesn't return `200`, set `corretto_affected_build` to the exact build
your PoC targets, or stage the artifact yourself and point
`corretto_affected_url_override` at it (see `variables.tf`). If the download
fails at boot, the node still comes up and reads **JDK INSTALL FAILED** — never
a misleading "not exposed".

## Deploy

```bash
git clone https://github.com/mamonaco1973/aws-java4shell.git
cd aws-java4shell
./apply.sh
```

`validate.sh` then prints each node's live verdict against its intended one:

```
NODE           VERDICT      EXPECTED     JAVA       VBMI   RESULT
---------------------------------------------------------------------------------------
vuln-x86       EXPOSED      EXPOSED      21.0.13    yes    PASS
safe-arm       NOT_EXPOSED  NOT_EXPOSED  21.0.13    no     PASS
patched-x86    NOT_EXPOSED  NOT_EXPOSED  21.0.13.1  yes    PASS

=================================================================================
  Java4Shell (CVE-2026-114938) — lab validation
=================================================================================
  RESULT: all nodes match their intended verdict. Lab is ready.
=================================================================================
```

## Try it

1. **See a verdict page.** Open an SSM tunnel to a node's web server and browse it:
   ```bash
   ID=$(terraform -chdir=01-java4shell output -json node_ids | jq -r '."vuln-x86"')
   aws ssm start-session --target "$ID" \
     --document-name AWS-StartPortForwardingSession \
     --parameters '{"portNumber":["80"],"localPortNumber":["8088"]}'
   # then open http://localhost:8088/
   ```
2. **Triage the fleet:** `./fleet-query.sh` — one line per node, EXPOSED first.
3. **Reach the decoder** (the exposure surface) the same way, forwarding
   `8080`, and point your `calif.io/java4shell` PoC at `localhost`.
4. **Remediate:** `./patch.sh`, then `./lab-verdicts.sh vuln-x86` — the
   verdict flips to `NOT_EXPOSED`.

## Teardown

```bash
./destroy.sh
```

## The vulnerability, briefly

| | |
|---|---|
| **CVE** | CVE-2026-114938 ("Java4Shell") |
| **Flaw** | memory corruption in HotSpot's AVX-512 `java.util.Base64` decode intrinsic, reachable pre-auth when a service decodes attacker-controlled Base64 |
| **Severity** | CVSS 4.0 **9.2** (Calif) / CVSS 3.1 **8.1** (Oracle/OpenJDK) |
| **Affected** | OpenJDK 17 (`17.0.6`→`17.0.21`), 21 (→`21.0.13`), 25 (→`25.0.5`), 27 (→`27.0.1`) on x86-64 **with AVX-512 VBMI**; ARM64 not affected |
| **Fixed** | `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` (Corretto: `…​.1.2` builds) — Oracle CPU of 2026-11-17 |
| **Temporary mitigation** | `-XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics` **or** `-XX:UseAVX=2` (x86-only; keeps AVX2, drops AVX-512). Stopgaps only — upgrade is the fix. |

Sources: [DigiCert advisory](https://www.digicert.com/security-advisories/java4shell-vulnerabilities-what-you-need-to-know),
[OpenJDK advisory (2026-11-17)](https://openjdk.org/groups/vulnerability/advisories/2026-11-17),
[Oracle CPU](https://www.oracle.com/security-alerts/cspunov2026.html), Red Hat RHSB-2026-018.

## Notes

- **Lab only.** Intentionally vulnerable; private subnets; SSM-only; HTTP served
  to localhost over an SSM tunnel. Not for production.
- **JDK source.** Amazon Corretto, pinned by build string in `variables.tf`.
- **Exploit code.** Not in this repo by design — bring your own isolated PoC.
