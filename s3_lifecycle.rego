package main

# 1. Main rule: Identifies buckets missing a lifecycle config
deny[msg] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_s3_bucket"
    bucket_address := resource.address

    # Validate against the configuration block
    not bucket_has_lifecycle_config(bucket_address)

    msg := sprintf("Violation: S3 bucket '%v' does not have an associated lifecycle configuration.", [bucket_address])
}

# 2. Helper: Links the lifecycle resource to the bucket in the HCL configuration
bucket_has_lifecycle_config(bucket_address) {
    some i, j
    resource := input.configuration.root_module.resources[i]
    resource.type == "aws_s3_bucket_lifecycle_configuration"

    # Verifies the reference exists in the expressions block
    ref := resource.expressions.bucket.references[j]
    startswith(ref, bucket_address)
}

# 3. Decision rule: This MUST match your OPA Deciding Query in StackGuardian
is_compliant {
    count(deny) == 0
}
