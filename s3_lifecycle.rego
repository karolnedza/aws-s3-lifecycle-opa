package terraform.s3

# This line is the "magic" that makes modern OPA CLI and 
# platforms like StackGuardian work together.
import future.keywords.if
import future.keywords.contains

# --- S3 LIFECYCLE RULES ---
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_s3_bucket"
    not bucket_has_lifecycle_config(resource.address)
    msg := sprintf("S3 Violation: Bucket '%v' is missing a lifecycle configuration.", [resource.address])
}

bucket_has_lifecycle_config(bucket_address) if {
    some i, j
    resource := input.configuration.root_module.resources[i]
    resource.type == "aws_s3_bucket_lifecycle_configuration"
    ref := resource.expressions.bucket.references[j]
    startswith(ref, bucket_address)
}

# --- RDS & AURORA RETENTION RULES ---
db_types := {"aws_db_instance", "aws_rds_cluster"}

deny contains msg if {
    some i
    resource := input.resource_changes[i]
    db_types[resource.type]

    env := get_attribute(resource, "tags").Environment
    env == "Production"

    retention := get_attribute(resource, "backup_retention_period")
    retention <= 14
    msg := sprintf("RDS Violation: Production DB '%v' has %v days retention. Must be > 14.", [resource.address, retention])
}

deny contains msg if {
    some i
    resource := input.resource_changes[i]
    db_types[resource.type]

    env := get_attribute(resource, "tags").Environment
    env != "Production"

    retention := get_attribute(resource, "backup_retention_period")
    retention != 1
    msg := sprintf("RDS Violation: Non-prod DB '%v' has %v days retention. Must be exactly 1 day.", [resource.address, retention])
}

# --- HELPERS ---
get_attribute(res, attr) = val if {
    val := res.change.after[attr]
    val != null
} else = val if {
    some i
    config_res := input.configuration.root_module.resources[i]
    config_res.address == res.address
    val := config_res.expressions[attr].constant_value
} else = 0

# --- STATUS RULES ---
allow := true if {
    count(deny) == 0
} else := false

status := "Pass" if {
    allow
} else := "Fail"
