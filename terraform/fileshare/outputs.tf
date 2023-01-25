output "domain_name" {
  value       = aws_cloudfront_distribution.s3_distribution.domain_name
  description = "The domain name of the CloudFront distribution."
}

output "files_bucket" {
  value       = aws_s3_bucket.b.id
  description = "The name of the files bucket."
}

output "logs_bucket" {
  value       = aws_s3_bucket.logs.id
  description = "The name of the logs bucket."
}
