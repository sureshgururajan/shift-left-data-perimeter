## Data-Perimeter Review Finding: Potential External Exfiltration Path

**Status:** NEEDS HUMAN REVIEW

- **Affected resources:** IAM Resource `DataProcessorRoleDefaultPolicy391E0388`, Policy `Policy`.
- **Risk:** The role gains `s3:PutObject` permissions on `ProdWorkloadBucket5555E521.Arn/*`, but the statement does not restrict principals or destinations using organizational condition keys (`aws:PrincipalOrgID` / `aws:ResourceOrgID`). If this role is subsequently exploited via a confused-deputy path, data can egress to an unmonitored external account.
- **Remediation:** Add an `aws:ResourceOrgID` condition key via a Resource Control Policy (RCP), or an `aws:PrincipalOrgID` condition key, or confirm this change against the approved-vendor exception manifest (`EXC-2026-04`).
- **Required action:** A human reviewer must verify exception scope or update the policy before merge.
