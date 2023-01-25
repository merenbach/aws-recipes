variable "access_log_retention_days" {
  type    = number
  default = 365
}

# Set your CloudFront domain names here
variable "cloudfront_aliases" {
  type    = list(string)
  default = null
}

# Set your allowed country codes here
# Leave null to allow access from anywhere
variable "cloudfront_allow_from" {
  type    = list(string)
  default = null

  # Consider limiting allowed country codes to where you expect traffic
  # default = ["US", "BR"]
}

# Per <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-cache-policies.html>
variable "cloudfront_cache_policy_id" {
  type    = string
  default = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  # default = "2e54312d-136d-493c-8eb9-b001f22f67d2" # Amplify
}

# Set your certificate ARN here
variable "cloudfront_certificate_arn" {
  type    = string
  default = null
}

variable "generator" {
  type    = string
  default = "Example"
}

variable "resource_naming_prefix" {
  type = string
  # A hyphen will be automatically appended
  default = "fileshare"
}
