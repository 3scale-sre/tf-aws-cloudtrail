
output "cloudtrail_bucket_name" {
  value = module.cloudtrail_bucket.this_s3_bucket_id
}