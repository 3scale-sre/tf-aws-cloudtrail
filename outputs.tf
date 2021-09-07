
output "cloudtrail_bucket_name" {
  value = module.cloudtrail_bucket.s3_bucket_id
}