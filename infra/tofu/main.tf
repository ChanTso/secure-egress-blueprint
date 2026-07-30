module "egress_node" {
  count  = var.deployment_enabled ? 1 : 0
  source = "./modules/egress-node"

  deployment_authorized = (
    var.deployment_acknowledgement == "CREATE_SYNTHETIC_REFERENCE_RESOURCES"
  )
  name_prefix                      = var.name_prefix
  availability_zone                = var.availability_zone
  blueprint_id                     = var.blueprint_id
  bundle_id                        = var.bundle_id
  ssh_key_pair_name                = var.ssh_key_pair_name
  tls_source_cidrs                 = var.tls_source_cidrs
  ssh_enabled                      = var.ssh_enabled
  ssh_source_cidrs                 = var.ssh_source_cidrs
  network_alarm_bytes              = var.network_alarm_bytes
  network_alarm_evaluation_periods = var.network_alarm_evaluation_periods
  network_alarm_contact_protocols  = var.network_alarm_contact_protocols
  enable_network_alarm             = var.enable_network_alarm
  protect_from_destroy             = var.protect_from_destroy
}

