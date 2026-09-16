# Documentation

Complete documentation for the Rental Management API project.

## Documentation Structure

### 📚 Core Documentation

1. **[Getting Started](01-GETTING_STARTED.md)** - Quick setup and development workflow
   - Installation instructions
   - Running locally
   - Common commands
   - Project structure
   - Troubleshooting

2. **[API Reference](02-API.md)** - Complete endpoint documentation
   - Authentication endpoints
   - Tenant endpoints
   - Request/response formats
   - Error handling
   - Rate limiting
   - CORS configuration

3. **[Architecture](03-ARCHITECTURE.md)** - System design and module overview
   - Architecture diagram
   - Module breakdown
   - Data flows
   - Request lifecycle
   - Security architecture
   - Scalability notes

4. **[Database Schema](04-DATABASE.md)** - Database tables and relationships
   - Table descriptions
   - Column details
   - Entity relationships
   - Common queries
   - Data integrity constraints
   - Indexes and optimization

5. **[Security Guide](05-SECURITY.md)** - Security practices and best practices
   - Authentication & authorization
   - Password security (PBKDF2)
   - Token management
   - Input validation
   - Database security
   - API security
   - Incident response

6. **[Deployment Guide](06-DEPLOYMENT.md)** - Production deployment steps
   - Prerequisites
   - Pre-deployment checklist
   - Cloudflare setup
   - Database migrations
   - Environment configuration
   - Testing procedures
   - Deployment steps
   - Post-deployment verification
   - Troubleshooting
   - Maintenance

7. **[Contributing Guide](07-CONTRIBUTING.md)** - Contributing to the project
   - Code of conduct
   - Development workflow
   - Code style guidelines
   - Testing requirements
   - Pull request process
   - Release process
   - Documentation standards

8. **[WebSocket System](08-WEBSOCKET.md)** - Real-time communication guide
   - Architecture overview
   - Security model
   - API endpoints for tickets
   - WebSocket connection protocol
   - Message types and format
   - Client implementation examples
   - Database schema for WebSocket
   - Performance notes
   - Future enhancements

9. **[WebSocket Setup Guide](09-WEBSOCKET_SETUP.md)** - Integration instructions
   - Prerequisites
   - Integration checklist
   - Database setup
   - Code integration
   - Configuration
   - Customization guide
   - Testing procedures
   - Deployment steps
   - Troubleshooting
   - IoT device authentication

---

## Quick Navigation

### For Developers

**Starting development?**
→ Read [Getting Started](01-GETTING_STARTED.md)

**Need API details?**
→ Check [API Reference](02-API.md)

**Understanding the code?**
→ Review [Architecture](03-ARCHITECTURE.md)

**Contributing code?**
→ Follow [Contributing Guide](07-CONTRIBUTING.md)

### For DevOps/Operations

**Deploying to production?**
→ Follow [Deployment Guide](06-DEPLOYMENT.md)

**Setting up database?**
→ See [Database Schema](04-DATABASE.md)

**Securing the system?**
→ Read [Security Guide](05-SECURITY.md)

### For Product/Project Managers

**Understanding the system?**
→ Read [Architecture](03-ARCHITECTURE.md) overview

**API capabilities?**
→ Check [API Reference](02-API.md)

**Security posture?**
→ Review [Security Guide](05-SECURITY.md)

---

## Key Information at a Glance

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Cloudflare Workers |
| Database | D1 (SQLite) |
| Language | JavaScript (ES Modules) |
| Authentication | JWT (jose v6.1.3) |
| Cryptography | PBKDF2-SHA256, Web Crypto API |
| Build Tool | esbuild |
| CLI | Wrangler |

### Project Structure

```
rental-management-api/
├── src/
│   ├── worker.js           # Main entry point
│   ├── auth.js             # Authentication endpoints
│   ├── tenant.js           # Tenant CRUD operations
│   └── lib/
│       ├── crypto.js       # Cryptographic utilities
│       ├── validation.js   # Input validation
│       └── rateLimit.js    # Rate limiting
├── migrations/
│   └── 0001_initial.sql    # Database schema
├── tests/
│   └── validation.test.js  # Test suite
├── docs/                   # This folder
├── dist/                   # Built output
├── package.json
├── wrangler.jsonc
└── README.md
```

### Core Concepts

**Authentication:**
- User signup with invitation codes
- Login with JWT token issuance
- Refresh token mechanism for new access tokens
- Password reset flow with time-limited tokens

**Authorization:**
- Role-based access control (admin, tenant, user)
- Tenant data isolation
- Admin-only operations

**Data Security:**
- PBKDF2-SHA256 password hashing (100k iterations)
- Parameterized database queries
- Input validation and sanitization
- Rate limiting on auth endpoints

**Database:**
- 5 tables: users, tenants, refresh_tokens, password_resets, signup_keys
- Foreign key relationships
- Automatic schema application via migrations

### Key Endpoints

**Authentication:**
- `POST /api/signup` - Create account
- `POST /api/login` - Authenticate user
- `POST /api/refresh_token` - Get new access token
- `POST /api/update_password` - Change password
- `POST /api/request_reset` - Request password reset
- `POST /api/reset_password` - Complete password reset

**Tenant Operations:**
- `POST /api/tenants` - Create tenant (admin only)
- `GET /api/tenants` - List all tenants (admin only)
- `GET /api/tenants/:id` - Get tenant details
- `PUT /api/tenants/:id` - Update tenant
- `DELETE /api/tenants/:id` - Delete tenant (admin only)

### Development Commands

```bash
npm run dev          # Start local development server
npm run build        # Build for production
npm test             # Run test suite
npm run deploy       # Deploy to production
```

### Security Highlights

✓ PBKDF2-SHA256 password hashing
✓ JWT-based authentication
✓ Parameterized SQL queries
✓ Input validation on all endpoints
✓ Role-based authorization
✓ Rate limiting on auth endpoints
✓ CORS whitelist configuration
✓ Comprehensive error handling

---

## Common Tasks

### Setting Up Locally

```bash
git clone <repo>
npm install
npm run dev
npm test
```

See [Getting Started](01-GETTING_STARTED.md) for details.

### Adding New Endpoint

1. Add route in `src/worker.js`
2. Implement handler in appropriate module
3. Add validation in `src/lib/validation.js`
4. Add tests
5. Update `docs/02-API.md`

See [Contributing Guide](07-CONTRIBUTING.md) for details.

### Deploying to Production

1. Configure Cloudflare (secrets, database)
2. Run tests: `npm test`
3. Build: `npm run build`
4. Deploy: `npm run deploy`
5. Verify endpoints

See [Deployment Guide](06-DEPLOYMENT.md) for details.

### Fixing Security Issues

1. Review [Security Guide](05-SECURITY.md)
2. Implement fix
3. Add tests
4. Deploy
5. Monitor logs

### Understanding the Code

1. Start with [Architecture](03-ARCHITECTURE.md)
2. Review specific module documentation
3. Check [API Reference](02-API.md) for endpoint details
4. Read source code comments

---

## Documentation Maintenance

### Updating Documentation

When making changes:
1. Update relevant documentation file
2. Update table of contents if structure changes
3. Update any affected diagrams
4. Test all links are working
5. Commit with appropriate message

### Adding New Documentation

1. Create new `.md` file in `docs/` folder
2. Add to this README's table of contents
3. Link from appropriate places
4. Commit with documentation message

### Standards

All documentation should:
- Use clear, concise language
- Include code examples where applicable
- Have appropriate headers and structure
- Include table of contents for long docs
- Be kept in sync with code changes
- Include links to related documentation

---

## Getting Help

### Finding Answers

1. **Installation issues?** → [Getting Started](01-GETTING_STARTED.md) Troubleshooting
2. **API question?** → [API Reference](02-API.md)
3. **Security concern?** → [Security Guide](05-SECURITY.md)
4. **Database question?** → [Database Schema](04-DATABASE.md)
5. **Deployment issue?** → [Deployment Guide](06-DEPLOYMENT.md) Troubleshooting

### Reporting Issues

- Check existing documentation first
- Check GitHub Issues for similar problems
- Open new issue with:
  - Clear title
  - Detailed description
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment information

### Contributing Improvements

Found error in docs? Want to improve docs?

1. Fork repository
2. Create `docs/*` branch
3. Make improvements
4. Submit pull request

See [Contributing Guide](07-CONTRIBUTING.md).

---

## Document Map

```
docs/
├── README.md (this file)
├── 01-GETTING_STARTED.md      - Installation, setup, quick start
├── 02-API.md                   - Endpoint reference
├── 03-ARCHITECTURE.md          - System design, module breakdown
├── 04-DATABASE.md              - Schema, tables, queries
├── 05-SECURITY.md              - Security practices, guidelines
├── 06-DEPLOYMENT.md            - Production deployment steps
└── 07-CONTRIBUTING.md          - Contribution guidelines
```

---

## Version Information

**API Version:** 1.0.0
**Compatibility Date:** 2026-01-26
**Node.js:** 18.0+
**Last Updated:** 2026-08-19

---

## Additional Resources

### External Documentation

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [D1 Database Docs](https://developers.cloudflare.com/d1/)
- [Wrangler CLI Docs](https://developers.cloudflare.com/workers/wrangler/)
- [OWASP Security Guidelines](https://owasp.org/)

### Related Files

- [README.md](../README.md) - Project overview
- [package.json](../package.json) - Dependencies
- [wrangler.jsonc](../wrangler.jsonc) - Cloudflare configuration
- [migrations/](../migrations/) - Database schema files
- [src/](../src/) - Source code
- [tests/](../tests/) - Test suite

---

**Questions?** Start with [Getting Started](01-GETTING_STARTED.md) or relevant documentation above.

**Contributing?** Follow the [Contributing Guide](07-CONTRIBUTING.md).

**Deploying?** Check the [Deployment Guide](06-DEPLOYMENT.md).
