variable "deployment_authorized" {
  description = "Blocking authorization interlock supplied by the root module."
  type        = bool
  sensitive   = true

  validation {
    condition     = var.deployment_authorized
    error_message = "Resource creation requires the explicit deployment acknowledgement."
  }
}

variable "name_prefix" {
  type = string
}

variable "availability_zone" {
  type = string
}

variable "blueprint_id" {
  type = string
}

variable "bundle_id" {
  type = string
}

variable "ssh_key_pair_name" {
  type     = string
  default  = null
  nullable = true
}

variable "tls_source_cidrs" {
  type = set(string)
}

variable "ssh_enabled" {
  type = bool
}

variable "ssh_source_cidrs" {
  type = set(string)
}

variable "enable_network_alarm" {
  type = bool
}

variable "network_alarm_bytes" {
  type = number
}

variable "network_alarm_evaluation_periods" {
  type = number
}

variable "network_alarm_contact_protocols" {
  type = set(string)
}

variable "protect_from_destroy" {
  type = bool

  validation {
    condition     = var.protect_from_destroy
    error_message = "Destroy protection is mandatory in this reference module."
  }
}

