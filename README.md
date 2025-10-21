# Enterprise Cross-Account S3 Access with KMS Encryption
## AWS Identity Center Implementation Guide

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Use Case Scenario](#use-case-scenario)
3. [Architecture Overview](#architecture-overview)
4. [Prerequisites](#prerequisites)
5. [Security Principles](#security-principles)
6. [Implementation Steps](#implementation-steps)
7. [Policy Explanations](#policy-explanations)
8. [Testing and Validation](#testing-and-validation)
9. [Client Access Guide](#client-access-guide)
10. [Troubleshooting](#troubleshooting)
11. [Maintenance and Operations](#maintenance-and-operations)
12. [Appendices](#appendices)

---

## Executive Summary

This document provides a comprehensive guide for implementing secure, enterprise-grade cross-account Amazon S3 access between AWS accounts managed by AWS IAM Identity Center (formerly AWS SSO). The solution enables external clients to securely access specific folders within an encrypted S3 bucket while maintaining strict security controls and compliance with AWS best practices.

**Key Features:**
- Cross-account S3 access using IAM Identity Center
- KMS-encrypted data protection
- Folder-level access restrictions (least privilege)
- Production-ready security controls
- Audit-compliant configuration

---

## Use Case Scenario

### Business Context

**Company:** Enterprise Financial Services Corp (Account A)  
**Partner:** External Audit Firm LLC (Account B)

### Scenario Description

Enterprise Financial Services Corp needs to provide their external audit firm with secure access to audit documents stored in an encrypted S3 bucket. The company has the following requirements:

#### Business Requirements:
1. **Data Segregation:** Audit files must be isolated in a dedicated folder (`client-data/`)
2. **Secure Access:** External auditors must authenticate through their own AWS Identity Center
3. **Data Protection:** All data must remain encrypted at rest using KMS Customer Managed Keys (CMK)
4. **Access Control:** Auditors should only access their specific folder, nothing else
5. **Audit Trail:** All access must be logged and traceable
6. **Compliance:** Solution must meet SOC 2, HIPAA, and financial industry standards

#### Technical Requirements:
1. Both organizations use AWS Organizations with Identity Center (SSO)
2. Data encryption using AWS KMS with Customer Managed Keys (CMK)
3. Principle of least privilege at all levels
4. No long-term credentials (no IAM users with access keys)
5. Time-limited sessions with automatic expiration
6. Production-grade security and reliability

### Accounts Information

| Account | ID | Role | Organization |
|---------|-----|------|--------------|
| Account A | 418649672840 | Data Owner (Financial Services) | Managed by Identity Center |
| Account B | 533267321107 | Data Consumer (Audit Firm) | Managed by Identity Center |

### Resources

| Resource | Details |
|----------|---------|
| **S3 Bucket** | `felix-bucket-123456-xyz` |
| **Bucket Region** | `us-east-2` |
| **KMS Key ARN** | `arn:aws:kms:us-east-2:418649672840:key/mrk-5382d625177c4eb6839afe8ede6bf67e` |
| **Access Folder** | `client-data/` |
| **Encryption** | AES-256 with KMS CMK |

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Account A (Owner)                        │
│                      ID: 418649672840                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              KMS Customer Managed Key                 │      │
│  │  arn:aws:kms:us-east-2:418649672840:key/mrk-...     │      │
│  │                                                       │      │
│  │  Key Policy:                                         │      │
│  │  • Account A: Full access                            │      │
│  │  • Account B: Decrypt & DescribeKey                  │      │
│  └──────────────────────────────────────────────────────┘      │
│                           │                                      │
│                           │ Encrypts/Decrypts                   │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────┐      │
│  │         S3 Bucket: felix-bucket-123456-xyz          │      │
│  │                                                       │      │
│  │  Structure:                                          │      │
│  │  ├── client-data/        ← Shared folder            │      │
│  │  │   ├── file1.pdf                                  │      │
│  │  │   └── file2.xlsx                                 │      │
│  │  └── internal-files/     ← Private (no access)      │      │
│  │                                                       │      │
│  │  Bucket Policy:                                      │      │
│  │  • Allows Account B access to client-data/* only    │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Cross-Account Access
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│                      Account B (Consumer)                      │
│                      ID: 533267321107                         │
├───────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────┐      │
│  │         AWS IAM Identity Center (SSO)              │      │
│  │                                                     │      │
│  │  Users:                                            │      │
│  │  • auditor1@auditfirm.com                         │      │
│  │  • auditor2@auditfirm.com                         │      │
│  └────────────────────────────────────────────────────┘      │
│                           │                                    │
│                           │ Assumes                            │
│                           ▼                                    │
│  ┌────────────────────────────────────────────────────┐      │
│  │         Permission Set: CrossAccountS3Access       │      │
│  │                                                     │      │
│  │  Inline Policy:                                    │      │
│  │  • S3: GetObject, PutObject, ListBucket            │      │
│  │    (only for client-data/* prefix)                 │      │
│  │  • KMS: Decrypt, Encrypt, GenerateDataKey          │      │
│  │                                                     │      │
│  │  Creates temporary role:                           │      │
│  │  AWSReservedSSO_CrossAccountS3Access_xxxxx         │      │
│  └────────────────────────────────────────────────────┘      │
│                                                                │
└────────────────────────────────────────────────────────────────┘

Access Flow:
1. User logs into Identity Center Access Portal
2. Selects CrossAccountS3Access permission set
3. Identity Center creates temporary credentials (1 hour)
4. User accesses S3 via console URL or AWS CLI
5. Request validated against bucket policy (Account A)
6. KMS decrypts data using cross-account key policy
7. User downloads/uploads files in client-data/ folder
```

### Security Layers

The solution implements **defense in depth** with multiple security layers:

1. **Authentication Layer:** AWS Identity Center (SSO) with MFA
2. **Authorization Layer 1:** IAM Permission Set (Identity-based policy)
3. **Authorization Layer 2:** S3 Bucket Policy (Resource-based policy)
4. **Encryption Layer:** KMS Key Policy controls encryption/decryption
5. **Network Layer:** AWS PrivateLink (optional, for enhanced security)
6. **Audit Layer:** CloudTrail logs all API calls

---

## Prerequisites

### Account A (Data Owner) Requirements

- [x] AWS Account with Organizations enabled
- [x] IAM Identity Center configured
- [x] S3 bucket created and configured
- [x] KMS Customer Managed Key (CMK) created
- [x] S3 bucket encrypted with KMS CMK
- [x] Administrative access to configure policies
- [x] CloudTrail enabled for audit logging

### Account B (Data Consumer) Requirements

- [x] AWS Account with Organizations enabled
- [x] IAM Identity Center configured
- [x] Users created in Identity Center
- [x] Administrative access to create permission sets
- [x] CloudTrail enabled for audit logging

### Required IAM Permissions

**For Administrator in Account A:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketPolicy",
        "s3:GetBucketPolicy",
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**For Administrator in Account B:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sso:CreatePermissionSet",
        "sso:PutInlinePolicyToPermissionSet",
        "sso:ProvisionPermissionSet",
        "sso:CreateAccountAssignment",
        "iam:ListRoles",
        "identitystore:ListUsers"
      ],
      "Resource": "*"
    }
  ]
}
```

### Knowledge Prerequisites

- Understanding of AWS IAM policies
- Familiarity with S3 bucket operations
- Basic knowledge of KMS encryption
- Experience with AWS Identity Center (SSO)
- Understanding of cross-account access patterns

---

## Security Principles

This implementation follows AWS Well-Architected Framework security best practices:

### 1. Principle of Least Privilege

**Definition:** Grant only the minimum permissions necessary to perform a task.

**Implementation:**
- Users can only access the `client-data/` folder, not the entire bucket
- Read and write permissions are explicitly defined
- No wildcard permissions on sensitive resources
- Folder-level restrictions at both IAM and S3 policy levels

### 2. Defense in Depth

**Definition:** Multiple layers of security controls to protect data.

**Implementation:**
- **Layer 1:** Identity Center authentication (MFA required)
- **Layer 2:** IAM Permission Set (identity-based policy)
- **Layer 3:** S3 Bucket Policy (resource-based policy)
- **Layer 4:** KMS Key Policy (encryption control)
- **Layer 5:** CloudTrail logging (audit trail)

### 3. Encryption at Rest and in Transit

**Definition:** Protect data when stored and when transmitted.

**Implementation:**
- S3 objects encrypted with KMS CMK (at rest)
- TLS 1.2+ for all API calls (in transit)
- KMS key rotation enabled (annually)
- Cross-account key access controlled via key policy

### 4. Temporary Credentials

**Definition:** Use short-lived credentials instead of long-term access keys.

**Implementation:**
- Identity Center provides temporary STS credentials
- Session duration: 1 hour (configurable)
- No IAM users with access keys
- Automatic credential expiration and rotation

### 5. Audit and Monitoring

**Definition:** Track all access and changes for compliance and security.

**Implementation:**
- CloudTrail logs all S3 and KMS API calls
- S3 access logging enabled
- KMS key usage logging
- Regular access review and compliance checks

### 6. Separation of Duties

**Definition:** No single person should have complete control over a critical function.

**Implementation:**
- Account A controls the data and bucket policies
- Account B controls user access and permission sets
- Both accounts must approve access (bilateral control)
- Different administrators manage each account

---

## Implementation Steps

### Phase 1: Configure KMS Key Policy (Account A)

#### Step 1.1: Locate the KMS Key

**Objective:** Identify the KMS Customer Managed Key (CMK) used to encrypt the S3 bucket.

**Actions:**

1. Log into **AWS Console** for Account A (418649672840)
2. Navigate to **AWS Key Management Service (KMS)**
3. In the left menu, select **Customer managed keys**
4. Locate the key used for your S3 bucket encryption
5. Note the **Key ARN**: `arn:aws:kms:us-east-2:418649672840:key/mrk-5382d625177c4eb6839afe8ede6bf67e`

**How to Identify the Correct Key:**
- Check S3 bucket properties → Default encryption settings
- Look for key alias or description matching your bucket
- Verify the key creation date aligns with bucket creation

#### Step 1.2: Update KMS Key Policy

**Objective:** Grant Account B permission to use the KMS key for decryption and encryption operations.

**Why This Is Required:**
- S3 objects are encrypted with this KMS key
- Account B must decrypt objects when downloading
- Account B must encrypt objects when uploading
- Without this permission, all S3 operations will fail with "Access Denied"

**Actions:**

1. Click on the KMS key: `mrk-5382d625177c4eb6839afe8ede6bf67e`
2. Scroll to **Key policy** section
3. Click **Edit** button
4. Add the following statement to the existing policy (inside the `"Statement": []` array):

```json
{
  "Sid": "AllowAccountBToUseKey",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::533267321107:root"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

5. Click **Save changes**

**Complete KMS Key Policy Example:**

```json
{
  "Version": "2012-10-17",
  "Id": "key-consolepolicy-3",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::418649672840:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAccountBToUseKey",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::533267321107:root"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**Policy Element Explanations:**

| Element | Value | Explanation |
|---------|-------|-------------|
| `Sid` | "AllowAccountBToUseKey" | Statement ID for identification and auditing |
| `Effect` | "Allow" | Grants permission (vs "Deny") |
| `Principal.AWS` | "arn:aws:iam::533267321107:root" | Account B root principal - allows Account B to delegate to its roles |
| `Action` | "kms:Decrypt" | Allows decrypting objects when downloading |
| `Action` | "kms:DescribeKey" | Allows viewing key metadata (required for S3 operations) |
| `Resource` | "*" | Applies to this key (in context of this key policy) |

**Why Use Account Root as Principal:**
- Allows Account B to delegate permissions through IAM roles
- More flexible than specifying individual roles
- Account B controls which users/roles can actually use this permission
- Follows AWS best practice for cross-account access

**Security Note:**
- This does NOT give Account B unrestricted access
- Account B still needs proper IAM permissions
- S3 bucket policy provides additional access control
- This is necessary for cross-account KMS operations

---

### Phase 2: Configure S3 Bucket Policy (Account A)

#### Step 2.1: Create Folder Structure

**Objective:** Organize the S3 bucket with dedicated folders for different access levels.

**Actions:**

1. Navigate to **S3** service in AWS Console
2. Click on bucket: `felix-bucket-123456-xyz`
3. Click **Create folder**
4. Enter folder name: `client-data`
5. Click **Create folder**

**Recommended Folder Structure:**

```
felix-bucket-123456-xyz/
├── client-data/              ← Shared with Account B
│   ├── audit-reports/
│   ├── financial-statements/
│   └── supporting-documents/
├── internal-files/           ← Private (Account A only)
├── archive/                  ← Private (Account A only)
└── logs/                     ← Private (Account A only)
```

**Best Practice:**
- Use descriptive folder names
- Maintain consistent naming conventions
- Document folder purposes
- Implement folder-level access controls

#### Step 2.2: Update S3 Bucket Policy

**Objective:** Configure the bucket policy to allow Account B access to only the `client-data/` folder.

**Why This Is Required:**
- S3 bucket policies control access at the resource level
- Implements server-side access control (defense in depth)
- Provides an additional security layer beyond IAM
- Ensures that even with valid credentials, access is restricted

**Actions:**

1. In the S3 bucket, go to **Permissions** tab
2. Scroll to **Bucket policy** section
3. Click **Edit**
4. Replace or add the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAccountBRoleAccessToClientDataFolder",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::533267321107:root",
                    "arn:aws:iam::533267321107:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_CrossAccountS3Access_f5f8e903621fe91f"
                ]
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::felix-bucket-123456-xyz/client-data/*"
        },
        {
            "Sid": "AllowListingClientDataFolder",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::533267321107:root",
                    "arn:aws:iam::533267321107:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_CrossAccountS3Access_f5f8e903621fe91f"
                ]
            },
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::felix-bucket-123456-xyz",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "client-data/*"
                }
            }
        }
    ]
}
```

5. Click **Save changes**

**Policy Element Explanations:**

**Statement 1: Object Access (GetObject/PutObject)**

| Element | Value | Explanation |
|---------|-------|-------------|
| `Sid` | "AllowAccountBRoleAccessToClientDataFolder" | Descriptive statement identifier |
| `Effect` | "Allow" | Grants permission |
| `Principal.AWS` | Array with Account B root and specific role | Allows both the account and the specific Identity Center role |
| `Action` | "s3:GetObject" | Permission to download/read objects |
| `Action` | "s3:PutObject" | Permission to upload/write objects |
| `Resource` | "...felix-bucket-123456-xyz/client-data/*" | Only applies to objects inside client-data/ folder |

**Statement 2: Bucket Listing (ListBucket)**

| Element | Value | Explanation |
|---------|-------|-------------|
| `Sid` | "AllowListingClientDataFolder" | Descriptive statement identifier |
| `Action` | "s3:ListBucket" | Permission to list objects in the bucket |
| `Resource` | "...felix-bucket-123456-xyz" | Applies to the bucket itself (not objects) |
| `Condition.StringLike` | "s3:prefix": "client-data/*" | Restricts listing to only the client-data/ prefix |

**Why Two Statements:**
- `GetObject` and `PutObject` work on **objects** (Resource: `bucket/*`)
- `ListBucket` works on the **bucket** itself (Resource: `bucket`)
- Different resource ARNs require separate statements

**Security Implementation:**

1. **Folder-Level Restriction:**
   - Resource: `client-data/*` ensures access only to this folder
   - Other folders (`internal-files/`, `archive/`) are completely inaccessible

2. **Condition-Based Listing:**
   - `s3:prefix` condition restricts what prefixes can be listed
   - Users can only see objects starting with `client-data/`
   - Cannot enumerate other folders or objects

3. **Minimal Permissions:**
   - Only `GetObject` and `PutObject` granted (no delete)
   - No bucket configuration permissions
   - No ability to modify bucket policies or ACLs

**Common Permissions and Their Use:**

| Permission | Purpose | Included |
|------------|---------|----------|
| `s3:GetObject` | Download/read files | ✅ Yes |
| `s3:PutObject` | Upload/write files | ✅ Yes |
| `s3:ListBucket` | List folder contents | ✅ Yes (restricted) |
| `s3:DeleteObject` | Delete files | ❌ No (security) |
| `s3:GetBucketLocation` | Get bucket region | ❌ Not needed |
| `s3:GetObjectVersion` | Access versions | ❌ Not needed |

**Testing the Policy:**
Before proceeding, verify the policy syntax:
- AWS Console validates JSON when saving
- Look for policy warnings or errors
- Ensure no typos in ARNs or action names

---

### Phase 3: Configure IAM Identity Center Permission Set (Account B)

#### Step 3.1: Identify the SAML Provider

**Objective:** Locate the Identity Center SAML provider name for the trust policy.

**Why This Is Required:**
- Identity Center uses SAML federation for authentication
- The trust policy must reference the correct SAML provider
- Each Identity Center instance has a unique SAML provider name

**Actions:**

1. Log into **AWS Console** for Account B (533267321107)
2. Navigate to **IAM** service
3. In the left menu, click **Identity providers**
4. Note the SAML provider name (example: `AWSSSO_51f236dcd1d69e9c_DO_NOT_DELETE`)

**Important:** The SAML provider name will be unique to your Identity Center instance. Use the exact name you see.

#### Step 3.2: Create the Permission Set

**Objective:** Create a custom permission set in Identity Center that grants access to the S3 bucket in Account A.

**Why Use Permission Sets:**
- Permission sets are Identity Center's way of granting AWS permissions
- They create temporary IAM roles automatically
- More secure than permanent IAM roles
- Integrated with Identity Center authentication and MFA

**Actions:**

1. Navigate to **IAM Identity Center** service
2. In the left menu, click **Permission sets**
3. Click **Create permission set**
4. Select **Custom permission set**
5. Click **Next**

**Permission Set Configuration:**

6. **Permission set name:** `CrossAccountS3Access`
7. **Description:** `Cross-account access to S3 bucket felix-bucket-123456-xyz in Account A (418649672840) - restricted to client-data folder only`
8. **Session duration:** `1 hour` (or per your security requirements)
   - Shorter duration = more secure but less convenient
   - Common values: 1 hour (high security), 4 hours (balanced), 8 hours (convenience)
9. Click **Next**

**Session Duration Best Practices:**

| Duration | Use Case | Security Level |
|----------|----------|----------------|
| 15 minutes | Highly sensitive operations | Highest |
| 1 hour | Standard operations (recommended) | High |
| 4 hours | Extended work sessions | Medium |
| 8 hours | Full workday access | Lower |
| 12 hours | Not recommended for production | Lowest |

#### Step 3.3: Create Inline Policy

**Objective:** Define the specific permissions that users with this permission set will have.

**Actions:**

10. Under **Inline policy**, click **Create a custom permissions policy**
11. Paste the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3FolderAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::felix-bucket-123456-xyz/client-data/*"
        },
        {
            "Sid": "S3ListBucket",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::felix-bucket-123456-xyz",
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "client-data/*",
                        "client-data/"
                    ]
                }
            }
        },
        {
            "Sid": "KMSKeyAccess",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:us-east-2:418649672840:key/mrk-5382d625177c4eb6839afe8ede6bf67e"
        }
    ]
}
```

12. Click **Next**
13. Review all settings
14. Click **Create**

**Policy Statement Explanations:**

**Statement 1: S3 Object Operations**

```json
{
    "Sid": "S3FolderAccess",
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",      // Download files
        "s3:PutObject"       // Upload files
    ],
    "Resource": "arn:aws:s3:::felix-bucket-123456-xyz/client-data/*"
}
```

**Purpose:** Grants permission to read and write objects in the `client-data/` folder.

**Key Points:**
- `Resource` ends with `/*` to include all objects in the folder
- Only `GetObject` and `PutObject` - no delete or versioning
- Cross-account resource ARN (different account number in ARN)

**Statement 2: S3 Bucket Listing**

```json
{
    "Sid": "S3ListBucket",
    "Effect": "Allow",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::felix-bucket-123456-xyz",
    "Condition": {
        "StringLike": {
            "s3:prefix": [
                "client-data/*",   // Objects inside folder
                "client-data/"     // The folder itself
            ]
        }
    }
}
```

**Purpose:** Allows listing objects, but only within the `client-data/` prefix.

**Key Points:**
- `Resource` is the bucket itself (no `/*`)
- `Condition` restricts which prefixes can be listed
- Both `client-data/*` and `client-data/` are needed:
  - `client-data/` - to see the folder itself
  - `client-data/*` - to see contents inside the folder

**Why the Condition Is Critical:**
Without the condition, users could list ALL objects in the bucket, violating the principle of least privilege. The condition ensures they can only see their allowed folder.

**Statement 3: KMS Operations**

```json
{
    "Sid": "KMSKeyAccess",
    "Effect": "Allow",
    "Action": [
        "kms:Decrypt",           // Decrypt when downloading
        "kms:DescribeKey",       // View key metadata
        "kms:Encrypt",           // Encrypt when uploading
        "kms:GenerateDataKey"    // Generate data keys for encryption
    ],
    "Resource": "arn:aws:kms:us-east-2:418649672840:key/mrk-5382d625177c4eb6839afe8ede6bf67e"
}
```

**Purpose:** Grants permission to use the KMS key for encryption and decryption operations.

**KMS Action Explanations:**

| Action | When Used | Why Required |
|--------|-----------|--------------|
| `kms:Decrypt` | Downloading encrypted objects | Decrypt the data encryption key (DEK) |
| `kms:DescribeKey` | Any S3 operation | S3 service validates key accessibility |
| `kms:Encrypt` | Uploading new objects | Encrypt the data encryption key (DEK) |
| `kms:GenerateDataKey` | Uploading new objects | Generate a unique DEK for each object |

**How KMS Encryption Works with S3:**

1. **Upload Flow:**
   - S3 calls `kms:GenerateDataKey` to create a unique data encryption key (DEK)
   - S3 encrypts the object with the plaintext DEK
   - S3 stores the encrypted DEK with the object
   - Plaintext DEK is discarded

2. **Download Flow:**
   - S3 retrieves the encrypted DEK from object metadata
   - S3 calls `kms:Decrypt` to decrypt the DEK
   - S3 uses the plaintext DEK to decrypt the object
   - Plaintext DEK is discarded after use

**Why Cross-Account ARN:**
The KMS key is in Account A (418649672840), so the full cross-account ARN must be specified.

#### Step 3.4: Assign Permission Set to Users

**Objective:** Assign the permission set to specific Identity Center users who need access.

**Actions:**

1. In **IAM Identity Center**, click **AWS accounts** in the left menu
2. Select Account B (533267321107)
3. Click **Assign users or groups**
4. Select the **Users** tab
5. Check the boxes next to users who need access (e.g., `auditor1@auditfirm.com`)
6. Click **Next**
7. Select the **CrossAccountS3Access** permission set
8. Click **Next**
9. Review the assignment
10. Click **Submit**

**Important:** Users must log out and log back into the Identity Center Access Portal to see the new permission set.

**Assignment Best Practices:**

| Practice | Description | Benefit |
|----------|-------------|---------|
| **Group Assignment** | Assign to groups, not individual users | Easier management |
| **Naming Convention** | Use descriptive group names (e.g., `External-Auditors`) | Clear purpose |
| **Regular Review** | Review assignments quarterly | Remove unnecessary access |
| **Documentation** | Document why each user/group needs access | Audit compliance |
| **Least Privilege** | Only assign to users who truly need it | Minimize risk |

**What Happens Behind the Scenes:**

When a user logs in with this permission set, Identity Center:
1. Authenticates the user (with MFA if enabled)
2. Creates a temporary IAM role in Account B
3. Role name: `AWSReservedSSO_CrossAccountS3Access_<unique-id>`
4. Attaches the inline policy to the role
5. Provides temporary STS credentials (valid for
