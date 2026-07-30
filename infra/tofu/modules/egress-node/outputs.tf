output "instance_name" {
  value = aws_lightsail_instance.this.name
}

output "static_ipv4_address" {
  value = aws_lightsail_static_ip.this.ip_address
}

