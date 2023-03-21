variable "generator" {
  type    = string
  default = "Example"
}

variable "resource_naming_prefix" {
  type = string
  # A hyphen will be automatically appended
  default = "terraform-state"
}

variable "version_retention_days" {
  type    = number
  default = 365
}
