variable "deployment_enabled" {
  description = "Hard interlock. The default creates no resources."
  type        = bool
  default     = false
}

variable "deployment_acknowledgement" {
  description = "Required literal acknowledgement when deployment_enabled is true."
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_region" {
  description = "AWS region selected by an authorized operator."
  type        = string
  default     = "us-east-2"

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must use a conventional AWS region identifier."
  }
}

variable "availability_zone" {
  description = "Availability zone for the single reference node."
  type        = string
  default     = "us-east-2a"

  validation {
    condition     = startswith(var.availability_zone, var.aws_region)
    error_message = "availability_zone must belong to aws_region."
  }
}

variable "name_prefix" {
  description = "Synthetic prefix applied to managed resources."
  type        = string
  default     = "synthetic-egress"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.name_prefix))
    error_message = "name_prefix must be 3-32 lowercase letters, digits, or hyphens."
  }
}

variable "blueprint_id" {
  description = "Lightsail operating-system blueprint."
  type        = string
  default     = "ubuntu_24_04"
}

variable "bundle_id" {
  description = "Lightsail bundle selected after an independent cost review."
  type        = string
  default     = "nano_3_0"
}

variable "ssh_key_pair_name" {
  description = "Existing Lightsail SSH key name. OpenTofu does not manage private keys."
  type        = string
  default     = null
  nullable    = true
}

variable "tls_source_cidrs" {
  description = "Canonical non-/0 IPv4 network CIDRs allowed to reach the TLS listener."
  type        = set(string)
  default     = ["198.51.100.0/24"]

  validation {
    condition = (
      length(var.tls_source_cidrs) > 0
      && alltrue([
        for cidr in var.tls_source_cidrs : try(
          can(cidrnetmask(cidr))
          && tonumber(split("/", cidr)[1]) > 0
          && split("/", cidr)[0] == cidrhost(cidr, 0),
          false
        )
      ])
    )
    error_message = "TLS sources must be canonical, non-/0 IPv4 network CIDRs."
  }
}

variable "ssh_enabled" {
  description = "Whether to expose SSH. Disabled by default."
  type        = bool
  default     = false
}

variable "ssh_source_cidrs" {
  description = "Canonical non-/0 IPv4 administration CIDRs used only when SSH is enabled."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.ssh_source_cidrs : try(
        can(cidrnetmask(cidr))
        && tonumber(split("/", cidr)[1]) > 0
        && split("/", cidr)[0] == cidrhost(cidr, 0),
        false
      )
    ])
    error_message = "SSH sources must be canonical, non-/0 IPv4 network CIDRs."
  }
}

variable "enable_network_alarm" {
  description = "Create an observational NetworkOut spike alarm."
  type        = bool
  default     = false
}

variable "network_alarm_bytes" {
  description = "Synthetic five-minute NetworkOut warning threshold, not a billing cap."
  type        = number
  default     = 5368709120

  validation {
    condition     = var.network_alarm_bytes >= 1048576
    error_message = "network_alarm_bytes must be at least one MiB."
  }
}

variable "network_alarm_evaluation_periods" {
  description = "Number of fixed five-minute Lightsail periods evaluated by the alarm."
  type        = number
  default     = 1

  validation {
    condition = (
      var.network_alarm_evaluation_periods >= 1
      && var.network_alarm_evaluation_periods <= 288
      && floor(var.network_alarm_evaluation_periods) == var.network_alarm_evaluation_periods
    )
    error_message = "network_alarm_evaluation_periods must be an integer from 1 through 288."
  }
}

variable "network_alarm_contact_protocols" {
  description = "Optional Lightsail Email/SMS protocols; regional contact methods must already exist."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for protocol in var.network_alarm_contact_protocols :
      contains(["Email", "SMS"], protocol)
    ])
    error_message = "network_alarm_contact_protocols may contain only Email and SMS."
  }
}

variable "protect_from_destroy" {
  description = "Keep lifecycle deletion protection on the reference node and static IP."
  type        = bool
  default     = true

  validation {
    condition     = var.protect_from_destroy
    error_message = "The public reference implementation requires destroy protection."
  }
}

