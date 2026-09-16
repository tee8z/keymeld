# Render with scripts/render-locked-kms-policy.sh. This template grants no policy
# administrator and denies operations outside the fixed recovery/read-only set.
{
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "DenyOtherPrincipals",
      Effect: "Deny", Principal: "*", Action: "kms:*", Resource: "*",
      Condition: {ArnNotEquals: {"aws:PrincipalArn": $role}}
    },
    {
      Sid: "DenyAdministrationAndOtherCryptography",
      Effect: "Deny", Principal: "*", Resource: "*",
      NotAction: ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"]
    },
    {
      Sid: "DenyMissingOrUnapprovedAttestation",
      Effect: "Deny", Principal: "*", Resource: "*",
      Action: ["kms:GenerateDataKey", "kms:Decrypt"],
      Condition: {StringNotEqualsIgnoreCase: {"kms:RecipientAttestation:ImageSha384": $images}}
    },
    {
      Sid: "AllowMeasuredEnclaveRecovery",
      Effect: "Allow", Principal: {AWS: $role}, Resource: "*",
      Action: ["kms:GenerateDataKey", "kms:Decrypt"],
      Condition: {StringEqualsIgnoreCase: {"kms:RecipientAttestation:ImageSha384": $images}}
    },
    {
      Sid: "AllowPolicyInspection",
      Effect: "Allow", Principal: {AWS: $role}, Resource: "*",
      Action: ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"]
    }
  ]
}
