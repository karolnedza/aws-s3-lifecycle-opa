package main

# Imports for modern OPA CLI (MacBook) compatibility
import future.keywords.if
import future.keywords.contains

# 1. Main Deny Rule: Identifies buckets missing a lifecycle config
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_s3_bucket"
    
    # Check the HCL configuration block for a matching lifecycle link
    not bucket_has_lifecycle_config(resource.address)

    msg := sprintf("S3 Violation: Bucket '%v' is missing an aws_s3_bucket_lifecycle_configuration resource.", [resource.address])
}

# 2. Helper: Links the lifecycle resource to the bucket in the HCL configuration
# This handles the "(known after apply)" scenario by reading your HCL code
bucket_has_lifecycle_config(bucket_address) if {
    some i, j
    resource := input.configuration.root_module.resources[i]
    resource.type == "aws_s3_bucket_lifecycle_configuration"

    # Verifies the reference exists in the expressions block of the HCL
    ref := resource.expressions.bucket.references[j]
    startswith(ref, bucket_address)
}

# 3. Decision rule for StackGuardian (returns true/false)
# Match this to your Deciding Query: main.allow
allow := true if {
    count(deny) == 0
} else := false

# 4. Status rule for MacBook CLI (returns "Pass"/"Fail")
status := "Pass" if {
    allow
} else := "Fail"
