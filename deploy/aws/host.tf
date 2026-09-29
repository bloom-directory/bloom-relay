# Debian 13 (trixie), the platform relay packages are built and tested on.
data "aws_ami" "debian" {
  most_recent = true
  owners      = ["136693071363"] # Debian

  filter {
    name   = "name"
    values = ["debian-13-amd64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# One interface, two private addresses, each with its own Elastic IP:
# the control address (HAProxy) and the Browser ingress address (gateway).
# A dedicated ingress address keeps Browser source IPs intact for
# admission quotas.
resource "aws_network_interface" "relay" {
  subnet_id          = aws_subnet.public[0].id
  security_groups    = [aws_security_group.relay_host.id]
  private_ips_count  = 1
  ipv6_address_count = 2

  tags = { Name = "bloom-relay-${var.placement}" }
}

locals {
  control_private_ip = aws_network_interface.relay.private_ip
  ingress_private_ip = one(setsubtract(aws_network_interface.relay.private_ip_list, [aws_network_interface.relay.private_ip]))
}

resource "aws_eip" "control" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.relay.id
  associate_with_private_ip = local.control_private_ip

  tags = { Name = "bloom-relay-${var.placement}-control" }
}

resource "aws_eip" "ingress" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.relay.id
  associate_with_private_ip = local.ingress_private_ip

  tags = { Name = "bloom-relay-${var.placement}-ingress" }
}

resource "aws_instance" "relay" {
  ami                     = data.aws_ami.debian.id
  instance_type           = var.instance_type
  iam_instance_profile    = aws_iam_instance_profile.relay_host.name
  disable_api_termination = true
  ebs_optimized           = true

  primary_network_interface {
    network_interface_id = aws_network_interface.relay.id
  }

  # IMDSv2 only, one hop: containers or forwarded requests cannot reach it.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    kms_key_id            = aws_kms_key.relay.arn
    delete_on_termination = false
  }

  # Installation follows docs/package.md; nothing is configured at boot.
  lifecycle {
    ignore_changes = [ami]
  }

  tags = { Name = "bloom-relay-${var.placement}" }
}

# Recover onto new hardware when the underlying host fails; the instance
# keeps its addresses and volume.
resource "aws_cloudwatch_metric_alarm" "host_recover" {
  alarm_name          = "bloom-relay-${var.placement}-system-check"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  dimensions          = { InstanceId = aws_instance.relay.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = ["arn:aws:automate:${var.region}:ec2:recover", aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "host_instance_check" {
  alarm_name          = "bloom-relay-${var.placement}-instance-check"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_Instance"
  dimensions          = { InstanceId = aws_instance.relay.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
