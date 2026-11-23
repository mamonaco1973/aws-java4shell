# ================================================================================
# SSM Instance Role
# Grants each node the permissions the SSM agent needs to register as a managed
# node, accept Session Manager / Run Command sessions, and publish custom
# inventory. This is the only way onto these boxes — they sit in private
# subnets with no public IP, no SSH key, and an egress-only security group.
#
# IAM names are account-global, so a hardcoded name collides the moment this
# project is deployed twice anywhere in the account. Names derive from
# local.name instead.
# ================================================================================

resource "aws_iam_role" "ssm" {
  name = "${local.name}-ssm-role"

  # Only the EC2 service may assume this role.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-ssm-role" }
}

# AWS-managed policy with the ssm/ssmmessages/ec2messages permissions the agent
# needs for Session Manager and Run Command. It already includes ssm:PutInventory,
# but we grant it explicitly below too so the fleet-inventory feature does not
# silently break if AWS ever narrows the managed policy.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Each node publishes a Custom:Java4Shell inventory entry (its Java version,
# AVX-512 VBMI presence, and exposure verdict) via `aws ssm put-inventory`.
# fleet-query.sh then reads that custom type account-wide — the mechanism that
# finds affected Java even when it was installed from a tarball rather than a
# package the default inventory would see.
resource "aws_iam_role_policy" "put_inventory" {
  name = "${local.name}-put-inventory"
  role = aws_iam_role.ssm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ssm:PutInventory"
      Resource = "*"
    }]
  })
}

# EC2 cannot consume an IAM role directly — the instance profile is the wrapper
# that lets an instance attach one.
resource "aws_iam_instance_profile" "ssm" {
  name = "${local.name}-ssm-profile"
  role = aws_iam_role.ssm.name

  tags = { Name = "${local.name}-ssm-profile" }
}
