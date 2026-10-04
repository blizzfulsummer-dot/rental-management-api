# API Documentation

Complete reference for all Rental Management API endpoints.

## Base URL

- **Development**: `http://localhost:8787`
- **Production**: `https://rental-management.ehexibit.com`

## Authentication

Most endpoints require JWT authentication via the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

JWT tokens are issued by the login endpoint and contain user information and role.

---

## Authentication Endpoints

### POST /api/signup

Create a new user account.

**Request Body**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "code": "SIGNUP_KEY",
  "role": "tenant" | "user" | "admin"
}
```

**Validation Rules**
- Email: Valid email format required
- Password: Minimum 8 characters, must include uppercase, lowercase, number, and symbol
- Role: One of `tenant`, `user`, or `admin`
- Code: Valid signup invitation code

**Response** (201 Created)
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "tenant",
  "requires_change_password": false,
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc..."
}
```

**Error Responses**
- `400 Bad Request`: Invalid payload or validation failed
- `409 Conflict`: Email already exists
- `500 Internal Server Error`: Database error

---

### POST /api/login

Authenticate user and receive tokens.

**Request Body**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response** (200 OK)
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "tenant",
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc..."
}
```

**Error Responses**
- `400 Bad Request`: Invalid email or password
- `401 Unauthorized`: User not found or password incorrect
- `500 Internal Server Error`: Database error

**Rate Limiting**: 10 requests per 15 minutes per IP

---

### POST /api/refresh_token

Get a new access token using a refresh token.

**Request Body**
```json
{
  "refresh_token": "eyJhbGc..."
}
```

**Response** (200 OK)
```json
{
  "access_token": "eyJhbGc..."
}
```

**Error Responses**
- `400 Bad Request`: Invalid or expired refresh token
- `401 Unauthorized`: Token validation failed

---

### POST /api/update_password

Update user password (requires authentication).

**Headers**
```
Authorization: Bearer <access_token>
```

**Request Body**
```json
{
  "old_password": "CurrentPass123!",
  "new_password": "NewPass456!"
}
```

**Validation**
- Old password must match current password
- New password: Minimum 8 characters, must include uppercase, lowercase, number, and symbol

**Response** (200 OK)
```json
{
  "message": "Password updated successfully"
}
```

**Error Responses**
- `401 Unauthorized`: Invalid or missing JWT token
- `400 Bad Request`: Invalid password format or old password incorrect
- `500 Internal Server Error`: Database error

**Rate Limiting**: 10 requests per 15 minutes per IP

---

### POST /api/request_reset

Request a password reset token (for forgotten passwords).

**Request Body**
```json
{
  "email": "user@example.com"
}
```

**Response** (200 OK)
```json
{
  "message": "Password reset token sent",
  "reset_token": "eyJhbGc..."
}
```

**Note**: In production, token is typically sent via email. For testing, token is returned in response.

**Error Responses**
- `400 Bad Request`: Invalid email format
- `404 Not Found`: User not found
- `500 Internal Server Error`: Database error

**Rate Limiting**: 10 requests per 15 minutes per IP

---

### POST /api/reset_password

Reset password using reset token.

**Request Body**
```json
{
  "token": "eyJhbGc...",
  "new_password": "NewPass456!"
}
```

**Validation**
- Token must be valid and not expired (1 hour expiration)
- New password: Minimum 8 characters, must include uppercase, lowercase, number, and symbol

**Response** (200 OK)
```json
{
  "message": "Password reset successfully"
}
```

**Error Responses**
- `400 Bad Request`: Invalid token or password format
- `401 Unauthorized`: Token expired or invalid
- `500 Internal Server Error`: Database error

**Rate Limiting**: 10 requests per 15 minutes per IP

---

### POST /api/verify_jwt

Verify JWT token and get user information.

**Headers**
```
Authorization: Bearer <access_token>
```

**Response** (200 OK)
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "tenant"
}
```

**Error Responses**
- `401 Unauthorized`: Invalid or expired JWT token

## House Device Endpoints

### GET /api/houses/:houseId/devices

List devices associated with a house. Admins can list all devices; owners can
list devices for their own houses; tenants and users only receive devices
explicitly granted through `user_device_access`.

### POST /api/houses/:houseId/devices

Create a device in a house (admin or owner of that house only).

```json
{
  "name": "Main Gate",
  "type": "Switch"
}
```

### GET, PUT, DELETE /api/devices/:deviceId

Read or manage an individual device. Admins and the house owner can manage
inventory. A tenant or user can read/use a device only when the corresponding
`(user_id, device_id)` row exists in `user_device_access`; they cannot edit or
delete it.

The browser uses `POST /ws/ticket` with `houseId`, `deviceId`, and
`clientType: "web"` before sending a command to that device. Tickets are scoped
to one device, and tenant/user ticket issuance checks `user_device_access`.

---

## Tenant Endpoints

### POST /api/tenants

Create a new tenant record (admin only).

**Headers**
```
Authorization: Bearer <admin_token>
```

**Request Body**
```json
{
  "user_id": 1,
  "balance": 500.00,
  "deposit": 1500.00,
  "rent_amount": 1000.00,
  "billing_cycle": "monthly",
  "leased_unit": "Apt 101",
  "onboard_date": "2026-08-19"
}
```

**Validation**
- balance, deposit, rent_amount: Valid numbers (no NaN)
- rent_amount: Required
- leased_unit, onboard_date: Required strings

**Response** (201 Created)
```json
{
  "id": 1,
  "user_id": 1,
  "balance": 500.00,
  "deposit": 1500.00,
  "rent_amount": 1000.00,
  "billing_cycle": "monthly",
  "leased_unit": "Apt 101",
  "onboard_date": "2026-08-19",
  "created_at": "2026-08-19T10:30:00Z"
}
```

**Error Responses**
- `401 Unauthorized`: Not authenticated or insufficient permissions
- `400 Bad Request`: Invalid payload
- `500 Internal Server Error`: Database error

---

### GET /api/tenants

List all tenants (admin only).

**Headers**
```
Authorization: Bearer <admin_token>
```

**Response** (200 OK)
```json
{
  "tenants": [
    {
      "id": 1,
      "user_id": 1,
      "email": "tenant@example.com",
      "balance": 500.00,
      "deposit": 1500.00,
      "rent_amount": 1000.00,
      "leased_unit": "Apt 101",
      "onboard_date": "2026-08-19"
    }
  ]
}
```

**Error Responses**
- `401 Unauthorized`: Not authenticated or insufficient permissions
- `500 Internal Server Error`: Database error

---

### GET /api/tenants/:tenantId

Get tenant details.

**Headers**
```
Authorization: Bearer <access_token>
```

**URL Parameters**
- `tenantId`: Numeric tenant ID

**Permissions**
- Admin: Can view any tenant
- Tenant/User: Can only view their own tenant

**Response** (200 OK)
```json
{
  "id": 1,
  "user_id": 1,
  "balance": 500.00,
  "deposit": 1500.00,
  "rent_amount": 1000.00,
  "billing_cycle": "monthly",
  "leased_unit": "Apt 101",
  "onboard_date": "2026-08-19"
}
```

**Error Responses**
- `400 Bad Request`: Invalid tenant ID
- `401 Unauthorized`: Not authenticated or insufficient permissions
- `404 Not Found`: Tenant not found
- `500 Internal Server Error`: Database error

---

### PUT /api/tenants/:tenantId

Update tenant information.

**Headers**
```
Authorization: Bearer <access_token>
```

**URL Parameters**
- `tenantId`: Numeric tenant ID

**Request Body**
```json
{
  "balance": 600.00,
  "deposit": 1500.00,
  "rent_amount": 1000.00,
  "billing_cycle": "monthly",
  "leased_unit": "Apt 102"
}
```

**Permissions**
- Admin: Can update any tenant's fields
- Tenant/User: Cannot update via this endpoint (use password update instead)

**Response** (200 OK)
```json
{
  "message": "Tenant updated successfully"
}
```

**Error Responses**
- `400 Bad Request`: Invalid tenant ID or payload
- `401 Unauthorized`: Not authenticated or insufficient permissions
- `404 Not Found`: Tenant not found
- `500 Internal Server Error`: Database error

---

### DELETE /api/tenants/:tenantId

Delete a tenant record (admin only).

**Headers**
```
Authorization: Bearer <admin_token>
```

**URL Parameters**
- `tenantId`: Numeric tenant ID

**Response** (200 OK)
```json
{
  "message": "Tenant deleted successfully"
}
```

**Error Responses**
- `400 Bad Request`: Invalid tenant ID
- `401 Unauthorized`: Not authenticated or insufficient permissions
- `404 Not Found`: Tenant not found
- `500 Internal Server Error`: Database error

---

## Error Handling

All errors are returned in JSON format:

```json
{
  "error": "Error message describing what went wrong"
}
```

### Common HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 204 | No Content - Successful but no content returned |
| 400 | Bad Request - Invalid request format or validation failed |
| 401 | Unauthorized - Authentication required or invalid credentials |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists (e.g., duplicate email) |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

---

## CORS

The API supports CORS for the following origins:

- `https://test-front-env.pages.dev`
- `https://my-other-site.pages.dev`
- `https://rental-management.ehexibit.com`

To add additional origins, update the `ALLOWED_ORIGINS` array in `src/worker.js`.

---

## Rate Limiting

Authentication endpoints are rate limited to prevent abuse:

- **Limit**: 10 requests per 15 minutes
- **Scope**: Per IP address
- **Applies to**:
  - POST /api/signup
  - POST /api/login
  - POST /api/update_password
  - POST /api/request_reset
  - POST /api/reset_password

When rate limit is exceeded, you'll receive:
```json
{
  "error": "Too many requests"
}
```
Status: 429 Too Many Requests
