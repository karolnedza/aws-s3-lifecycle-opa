package terraform.s3

import future.keywords.if
import future.keywords.in

# 1. Main rule: Deny if a bucket exists in the plan but has no lifecycle config in the HCL
deny_missing_lifecycle contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    bucket_address := resource.address

    # Check the configuration block for a matching lifecycle link
    not bucket_has_lifecycle_config(bucket_address)

    msg := sprintf("Violation: S3 bucket '%v' does not have an associated lifecycle configuration.", [bucket_address])
}

# 2. Helper: Looks in the 'configuration' block for HCL-level references
# This is necessary because bucket IDs are often 'known after apply' in the resource_changes block 
bucket_has_lifecycle_config(bucket_address) if {
    # Scan the root module resources in the configuration
    some resource in input.configuration.root_module.resources
    resource.type == "aws_s3_bucket_lifecycle_configuration"

    # Check if the 'bucket' expression references our bucket's address (e.g., aws_s3_bucket.app_storage.id) [cite: 3]
    some ref in resource.expressions.bucket.references
    startswith(ref, bucket_address)
}

# 3. Status rule: Provides a simple "Pass" or "Fail" string for reporting
status := "Pass" if {
    count(deny_missing_lifecycle) == 0
} else := "Fail"
