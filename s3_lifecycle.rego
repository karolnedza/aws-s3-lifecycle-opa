package terraform.s3

# 1. Main rule: Deny if a bucket exists but has no lifecycle config in HCL
# Standard syntax: rule_name[msg] { ... }
deny_missing_lifecycle[msg] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_s3_bucket"
    bucket_address := resource.address

    # Check the configuration block for a matching lifecycle link
    not bucket_has_lifecycle_config(bucket_address)

    msg := sprintf("Violation: S3 bucket '%v' does not have an associated lifecycle configuration.", [bucket_address])
}

# 2. Helper: Looks in 'configuration' for HCL-level references
bucket_has_lifecycle_config(bucket_address) {
    some i, j
    resource := input.configuration.root_module.resources[i]
    resource.type == "aws_s3_bucket_lifecycle_configuration"

    # Match the bucket reference
    ref := resource.expressions.bucket.references[j]
    startswith(ref, bucket_address)
}

# 3. Boolean rule for StackGuardian's "Deciding Query"
# Returns true if there are zero deny messages
is_compliant {
    count(deny_missing_lifecycle) == 0
}
