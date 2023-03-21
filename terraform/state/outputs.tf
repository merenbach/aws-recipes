output "bucket_name" {
  value       = aws_s3_bucket.b.id
  description = "The name of S3 bucket to store state."
}

output "dynamodb_table" {
  value       = aws_dynamodb_table.d.id
  description = "The name of the DynamoDB table to store state."
}
