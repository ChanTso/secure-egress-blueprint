output "deployment_enabled" {
  description = "Whether the resource-creation interlock is open."
  value       = var.deployment_enabled
}

output "instance_name" {
  description = "Managed instance name, or null while the default interlock is closed."
  value       = try(module.egress_node[0].instance_name, null)
}

output "static_ipv4_address" {
  description = "Allocated static address, or null while the default interlock is closed."
  value       = try(module.egress_node[0].static_ipv4_address, null)
}

