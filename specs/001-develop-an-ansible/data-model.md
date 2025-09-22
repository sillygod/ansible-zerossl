# Data Model: Ansible ZeroSSL Plugin

## Core Entities

### Certificate
Represents an SSL/TLS certificate managed through ZeroSSL API.

**Attributes**:
- `id: str` - ZeroSSL certificate identifier
- `domains: List[str]` - List of domains covered by certificate
- `common_name: str` - Primary domain (first in domains list)
- `status: CertificateStatus` - Current certificate state
- `created_at: datetime` - Certificate creation timestamp
- `expires_at: datetime` - Certificate expiration timestamp
- `validation_method: ValidationMethod` - Domain validation approach used
- `certificate_path: Optional[str]` - Local filesystem path where certificate is stored

**State Transitions**:
```
draft → pending_validation → issued
               ↓
            canceled
               ↓
            expired
```

**Validation Rules**:
- At least one domain required
- Domains must be valid FQDN format
- Certificate path must be writable if specified
- Expiration date must be in the future for active certificates

### Domain Validation
Represents the validation process for proving domain ownership.

**Attributes**:
- `domain: str` - Domain being validated
- `method: ValidationMethod` - Validation approach (HTTP-01 or DNS-01)
- `challenge_token: str` - Validation token provided by ZeroSSL
- `challenge_url: str` - URL where validation file should be placed (HTTP-01)
- `cname_validation_p1: Optional[str]` - CNAME record name/host for DNS validation (DNS-01)
- `cname_validation_p2: Optional[str]` - CNAME record value/points-to for DNS validation (DNS-01)
- `status: ValidationStatus` - Current validation state
- `validated_at: Optional[datetime]` - Timestamp when validation completed

**Validation Rules**:
- Domain must match certificate domain list
- Challenge token must be non-empty
- HTTP-01 requires accessible web directory
- DNS-01 requires DNS management access

### API Credentials
Represents ZeroSSL API authentication information.

**Attributes**:
- `api_key: str` - ZeroSSL API access key (sensitive)
- `rate_limit_remaining: int` - Remaining API calls in current period
- `rate_limit_reset: datetime` - When rate limit counter resets

**Validation Rules**:
- API key must be valid ZeroSSL format
- Rate limiting must be respected

### Certificate Bundle
Represents the complete certificate package for deployment.

**Attributes**:
- `certificate: str` - Primary certificate content (PEM format)
- `private_key: str` - Private key content (PEM format)
- `ca_bundle: str` - Certificate authority chain (PEM format)
- `full_chain: str` - Combined certificate + CA bundle for web servers

**Validation Rules**:
- All components must be valid PEM format
- Certificate and private key must be cryptographically paired
- CA bundle must form valid trust chain

## Enumerations

### CertificateStatus
```python
class CertificateStatus(Enum):
    DRAFT = "draft"
    PENDING_VALIDATION = "pending_validation"
    ISSUED = "issued"
    EXPIRED = "expired"
    CANCELED = "canceled"
```

### ValidationMethod
```python
class ValidationMethod(Enum):
    HTTP_01 = "HTTP_CSR_HASH"  # ZeroSSL API format
    DNS_01 = "DNS_CSR_HASH"    # ZeroSSL API format
```

### ValidationStatus
```python
class ValidationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VALID = "valid"
    INVALID = "invalid"
```

### OperationState
```python
class OperationState(Enum):
    PRESENT = "present"      # Ensure certificate exists and is valid
    REQUEST = "request"      # Create certificate request only
    VALIDATE = "validate"    # Validate pending certificate
    DOWNLOAD = "download"    # Download issued certificate
    ABSENT = "absent"        # Remove/cancel certificate
    CHECK_RENEWAL = "check_renew_or_create"  # Check if renewal needed
```

## Entity Relationships

### Certificate ↔ Domain Validation
- **One-to-Many**: One certificate can have multiple domain validations
- **Cascade**: When certificate is canceled, all validations become invalid
- **Constraint**: All certificate domains must have corresponding validations

### API Credentials ↔ Certificate
- **One-to-Many**: One API key can manage multiple certificates
- **Dependency**: Certificate operations require valid API credentials
- **Rate Limiting**: All operations share the same rate limit pool

### Certificate ↔ Certificate Bundle
- **One-to-One**: Each issued certificate has exactly one bundle
- **Lifecycle**: Bundle is created when certificate reaches "issued" status
- **Storage**: Bundle components stored together or separately based on configuration

## Data Validation Matrix

| Field | Required | Format | Constraints |
|-------|----------|--------|-------------|
| domains | Yes | List[FQDN] | 1-100 domains, valid FQDN format |
| api_key | Yes | String | ZeroSSL API key format |
| certificate_path | No | Filesystem path | Must be writable directory |
| validation_method | No | Enum | HTTP_01 or DNS_01, default HTTP_01 |
| state | No | Enum | Valid OperationState, default PRESENT |
| renew_threshold_days | No | Integer | 1-365, default 30 |

## Storage Considerations

### Temporary Files
- Validation tokens stored in `/tmp/ansible-zerossl/`
- CSR files generated temporarily during operations
- Downloaded certificates cached briefly before final placement

### Persistent Storage
- Final certificates stored at user-specified paths
- Configuration state maintained in Ansible facts
- No sensitive data persisted unencrypted

### Cleanup Strategy
- Temporary files removed after operations complete
- Failed operation artifacts cleaned up automatically
- Old validation tokens expired after 7 days

This data model provides the foundation for implementing robust certificate management with clear entity relationships and validation rules.
