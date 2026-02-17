package main

# 1. Main rule: Returns a list of violations
deny[msg] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_s3_bucket"
    bucket_address := resource.address

    # Check the configuration block for a matching lifecycle link
    not bucket_has_lifecycle_config(bucket_address)

    msg := sprintf("Violation: S3 bucket '%v' does not have an associated lifecycle configuration.", [bucket_address])
}

# 2. Helper: Looks in the 'configuration' block for HCL-level references
bucket_has_lifecycle_config(bucket_address) {
    some i, j
    resource := input.configuration.root_module.resources[i]
    resource.type == "aws_s3_bucket_lifecycle_configuration"

    # Match the bucket reference
    ref := resource.expressions.bucket.references[j]
    startswith(ref, bucket_address)
}

# 3. Decision rule: StackGuardian will use this to PASS or FAIL
# This returns true only if the 'deny' list is empty
allow {
    count(deny) == 0
}
