# Security Documentation - Patronus Dashboard

## Overview

The Patronus SD-WAN Dashboard implements enterprise-grade security features to protect against common web vulnerabilities and ensure secure access to network management functions.

## Authentication & Authorization

### JWT-Based Authentication

The dashboard uses JSON Web Tokens (JWT) for stateless authentication:

- **Access Tokens**: Short-lived (15 minutes) tokens for API access
- **Refresh Tokens**: Long-lived (7 days) tokens for obtaining new access tokens
- **Token Storage**: Client-side storage in localStorage
- **Token Validation**: Server-side validation on every protected endpoint

#### Token Structure

```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "role": "admin|operator|viewer",
  "iat": 1234567890,
  "exp": 1234567890,
  "token_type": "access|refresh",
  "jti": "unique-token-id"
}
```

### Password Security

- **Algorithm**: Argon2id (memory-hard, GPU-resistant)
- **Strength Requirements**:
  - Minimum 12 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character
- **Hashing**: Performed server-side with secure defaults
- **Storage**: Only password hashes stored, never plaintext

### Role-Based Access Control (RBAC)

Three user roles with hierarchical permissions:

1. **Admin**: Full access to all features
   - User management
   - Policy management
   - System configuration
   - All monitoring features

2. **Operator**: Network operations
   - View sites, paths, and metrics
   - Create and modify policies
   - Monitor network health
   - No user management

3. **Viewer**: Read-only access
   - View dashboard
   - View metrics and logs
   - No modification rights

## Security Headers

The dashboard automatically sets the following HTTP security headers on all responses:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Header Descriptions

- **X-Content-Type-Options**: Prevents MIME-type sniffing attacks
- **X-Frame-Options**: Prevents clickjacking by disallowing iframe embedding
- **X-XSS-Protection**: Enables browser XSS filtering
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS connections

## API Endpoints

### Public Endpoints (No Authentication Required)

- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/init-admin` - Initial admin setup (only works if no users exist)
- `GET /health` - Health check

### Protected Endpoints (Authentication Required)

All other API endpoints require a valid JWT access token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Initial Setup

### First-Time Administrator Account

When no users exist in the system, anyone can create the initial admin account via:

1. Navigate to the login page
2. Click "Initialize Admin Account"
3. Provide:
   - Full name
   - Email address
   - Strong password (meeting requirements)
4. Submit to create the account

**Important**: After the first admin account is created, this endpoint becomes disabled. Only existing admins can create additional users.

## Session Management

### Token Lifecycle

1. **Login**: User provides email/password, receives access + refresh tokens
2. **API Access**: Client includes access token in requests
3. **Token Expiry**: After 15 minutes, access token expires
4. **Refresh**: Client uses refresh token to get new access token
5. **Logout**: Client clears all tokens from localStorage

### Automatic Session Handling

The frontend automatically:
- Checks for valid tokens on page load
- Redirects to login if no valid session
- Displays user info in header
- Provides logout functionality

## Security Best Practices

### For Deployment

1. **HTTPS Only**: Always deploy behind HTTPS/TLS
   - The HSTS header enforces this after first visit
   - Consider using a reverse proxy (nginx, Caddy) for TLS termination

2. **JWT Secret**: Change the default JWT secret in production
   - Located in `src/auth/jwt.rs`
   - Use a cryptographically random 32+ byte secret
   - Store in environment variable, not hardcoded

3. **Database Security**:
   - Use file permissions to protect `dashboard.db`
   - Consider encryption at rest for sensitive deployments
   - Regular backups with secure storage

4. **Network Security**:
   - Bind to localhost if using reverse proxy
   - Use firewall rules to limit access
   - Consider VPN or IP whitelisting

### For Developers

1. **Never Log Sensitive Data**:
   - No passwords in logs
   - No tokens in logs
   - Sanitize user input before logging

2. **Input Validation**:
   - Always validate on server side
   - Don't trust client-side validation
   - Use type-safe parsing

3. **Error Messages**:
   - Don't reveal internal details in errors
   - Use generic messages for auth failures
   - Log detailed errors server-side only

## Known Limitations & Future Enhancements

### Current Limitations

1. **No Rate Limiting**: Currently no built-in rate limiting
   - Consider deploying behind nginx with `limit_req`
   - Or add application-level rate limiting with `tower-governor`

2. **Single JWT Secret**: All tokens use same secret
   - Consider key rotation mechanism
   - Consider separate secrets per token type

3. **No Account Lockout**: Unlimited login attempts allowed
   - Add failed attempt tracking
   - Implement temporary account lockout

4. **No Session Revocation**: Tokens valid until expiry
   - Add token blacklist/revocation list
   - Consider shorter token lifetimes

5. **No 2FA/MFA**: Single-factor authentication only
   - Add TOTP support
   - Add WebAuthn/FIDO2 support

### Planned Enhancements

- [ ] Rate limiting on authentication endpoints
- [ ] Audit logging for security events
- [ ] Account lockout after failed attempts
- [ ] Token revocation/blacklist
- [ ] Two-factor authentication (TOTP)
- [ ] WebAuthn/FIDO2 support
- [ ] JWT key rotation
- [ ] IP-based access controls
- [ ] Session management dashboard
- [ ] Security event notifications

## Vulnerability Reporting

If you discover a security vulnerability in the Patronus Dashboard, please:

1. **Do NOT** open a public issue
2. Email security details to the maintainers
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We take security seriously and will respond promptly to legitimate security concerns.

## Compliance Considerations

### GDPR/Privacy

- User passwords are properly hashed and never stored in plaintext
- Email addresses are stored for authentication purposes
- No unnecessary personal data is collected
- Users can be deleted by admins (implement proper data removal)

### Audit Requirements

For compliance with security audit requirements:

1. Enable detailed logging (configure `RUST_LOG=info` or higher)
2. Collect logs to secure, centralized logging system
3. Monitor for suspicious authentication patterns
4. Implement log retention policy per regulations
5. Regular security reviews and updates

## Security Checklist for Production

- [ ] Change default JWT secret to cryptographically random value
- [ ] Deploy behind HTTPS/TLS (reverse proxy recommended)
- [ ] Set up firewall rules to limit access
- [ ] Configure secure database file permissions
- [ ] Enable detailed security logging
- [ ] Implement log monitoring and alerting
- [ ] Regular security updates and patching
- [ ] Password policy enforcement
- [ ] User access reviews
- [ ] Backup and disaster recovery plan

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Argon2 Specification](https://tools.ietf.org/html/rfc9106)
- [HSTS Specification](https://tools.ietf.org/html/rfc6797)

---

**Last Updated**: 2025-10-10
**Version**: 0.1.0
