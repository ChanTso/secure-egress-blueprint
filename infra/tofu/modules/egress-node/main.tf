resource "aws_lightsail_instance" "this" {
  name              = "${var.name_prefix}-node"
  availability_zone = var.availability_zone
  blueprint_id      = var.blueprint_id
  bundle_id         = var.bundle_id
  ip_address_type   = "ipv4"
  key_pair_name     = var.ssh_key_pair_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_lightsail_static_ip" "this" {
  name = "${var.name_prefix}-ipv4"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_lightsail_static_ip_attachment" "this" {
  static_ip_name = aws_lightsail_static_ip.this.name
  instance_name  = aws_lightsail_instance.this.name
}

resource "aws_lightsail_instance_public_ports" "this" {
  instance_name = aws_lightsail_instance.this.name

  port_info {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443
    cidrs     = sort(tolist(var.tls_source_cidrs))
  }

  dynamic "port_info" {
    for_each = var.ssh_enabled ? [1] : []
    content {
      protocol  = "tcp"
      from_port = 22
      to_port   = 22
      cidrs     = sort(tolist(var.ssh_source_cidrs))
    }
  }

  lifecycle {
    precondition {
      condition     = !var.ssh_enabled || length(var.ssh_source_cidrs) > 0
      error_message = "SSH exposure requires at least one narrow source CIDR."
    }
  }
}

resource "awscc_lightsail_alarm" "network_out" {
  count = var.enable_network_alarm ? 1 : 0

  alarm_name              = "${var.name_prefix}-network-out-spike"
  comparison_operator     = "GreaterThanOrEqualToThreshold"
  contact_protocols       = length(var.network_alarm_contact_protocols) == 0 ? null : sort(tolist(var.network_alarm_contact_protocols))
  evaluation_periods      = var.network_alarm_evaluation_periods
  metric_name             = "NetworkOut"
  monitored_resource_name = aws_lightsail_instance.this.name
  notification_enabled    = true
  notification_triggers   = ["ALARM"]
  threshold               = var.network_alarm_bytes
  treat_missing_data      = "breaching"
}
