# 🏠 Rental Management API with Smart Home WebSocket System

A complete Cloudflare Workers API for rental property management with real-time smart home IoT device communication.

## 🌟 Features

### Core API
- ✅ User authentication with JWT (HS256)
- ✅ Tenant management (create, read, update, delete)
- ✅ Password reset system with secure tokens
- ✅ User signup with invite codes
- ✅ Request validation and error handling
- ✅ Rate limiting on sensitive endpoints
- ✅ CORS support for frontend integration

### Real-time Smart Home (NEW!)
- ✅ **WebSocket Room System** - Per-house Durable Objects for real-time communication
- ✅ **Secure Tickets** - Short-lived, single-use tokens for WebSocket access
- ✅ **Device Commands** - Web clients send commands to IoT devices
- ✅ **Status Updates** - Devices broadcast real-time status to web clients
- ✅ **Session Management** - Track authenticated users and devices
- ✅ **Admin Monitoring** - See all active sessions in a house room
- ✅ **Keep-alive** - Ping/pong mechanism for connection stability

### Frontend (NEW!)
- ✅ **Dashboard UI** - Modern, responsive smart home control panel
- ✅ **Real-time Updates** - Live device status display
- ✅ **Device Control** - Send commands (turn on/off) to devices
- ✅ **Activity Log** - Real-time events and system messages
- ✅ **Multi-client** - Support multiple simultaneous users

### Testing Tools (NEW!)
- ✅ **Device Simulator** - Node.js IoT device for testing
- ✅ **Test Documentation** - Complete testing scenarios
- ✅ **API Examples** - curl and wscat commands

## 🚀 Quick Start

### 1. Install & Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The worker will:
- Start on `http://localhost:8787`
- Auto-apply database migrations
- Serve the frontend at `/`

### 2. Access Frontend

Open browser:
```
http://localhost:8787/
```

Login with demo credentials:
```
Email: admin@example.com
Password: AdminPass123!
```

### 3. Test with Device Simulator

In a new terminal:
```bash
npm run device:sim
```

You'll see:
- Device connects to WebSocket room
- Device appears in dashboard
- Simulate sending/receiving commands

## 📁 Project Structure

```
rental-management-api/
├── public/
│   └── index.html              # Frontend dashboard (NEW!)
├── src/
│   ├── auth.js                 # Authentication endpoints
│   ├── tenant.js               # Tenant CRUD operations
│   ├── worker.js               # Main request router
│   ├── houseRoom.js            # Durable Object for WebSocket (NEW!)
│   └── lib/
│       ├── rateLimit.js        # Rate limiting
│       └── websocketTicket.js  # Ticket system (NEW!)
├── migrations/
│   ├── 0001_init.sql          # Initial schema
│   └── 0002_smartroom.sql     # WebSocket system tables (NEW!)
├── docs/
│   ├── 01-GETTING_STARTED.md
│   ├── 02-API.md
│   ├── 03-ARCHITECTURE.md
│   ├── 04-DATABASE.md
│   ├── 05-SECURITY.md
│   ├── 06-DEPLOYMENT.md
│   ├── 07-CONTRIBUTING.md
│   ├── 08-WEBSOCKET.md        # WebSocket protocol (NEW!)
│   └── 09-WEBSOCKET_SETUP.md  # Integration guide (NEW!)
├── WEBSOCKET_INTEGRATION_SUMMARY.md  # Overview (NEW!)
├── FRONTEND_TESTING.md              # Frontend guide (NEW!)
├── TESTING_COMPLETE_SYSTEM.md       # Complete test guide (NEW!)
├── wrangler.jsonc              # Worker configuration
├── package.json
└── README.md (this file)
```

## 📖 Documentation

### Getting Started
- **[01-GETTING_STARTED.md](docs/01-GETTING_STARTED.md)** - Setup and basic usage
- **[FRONTEND_TESTING.md](FRONTEND_TESTING.md)** - Frontend dashboard walkthrough

### API & Architecture
- **[02-API.md](docs/02-API.md)** - Complete API reference
- **[03-ARCHITECTURE.md](docs/03-ARCHITECTURE.md)** - System design overview
- **[04-DATABASE.md](docs/04-DATABASE.md)** - Database schema

### Smart Home & WebSocket
- **[08-WEBSOCKET.md](docs/08-WEBSOCKET.md)** - WebSocket protocol details
- **[09-WEBSOCKET_SETUP.md](docs/09-WEBSOCKET_SETUP.md)** - Integration guide
- **[WEBSOCKET_INTEGRATION_SUMMARY.md](WEBSOCKET_INTEGRATION_SUMMARY.md)** - Quick overview

### Security & Deployment
- **[05-SECURITY.md](docs/05-SECURITY.md)** - Security best practices
- **[06-DEPLOYMENT.md](docs/06-DEPLOYMENT.md)** - Production deployment

### Testing & Contributing
- **[TESTING_COMPLETE_SYSTEM.md](TESTING_COMPLETE_SYSTEM.md)** - Full testing guide
- **[07-CONTRIBUTING.md](docs/07-CONTRIBUTING.md)** - Contributing guidelines

## 🧪 Testing Guide

### Basic Frontend Test (5 minutes)

```bash
# Terminal 1: Start server
npm run dev

# Browser: http://localhost:8787/
# Login with admin@example.com / AdminPass123!
```

### Full System Test (15 minutes)

```bash
# Terminal 1: Start server
npm run dev

# Browser: http://localhost:8787/
# Login with admin@example.com / AdminPass123!

# Terminal 2: Start device simulator
npm run device:sim

# Browser: Watch device appear and respond to commands
```

### API Testing (curl/wscat)

See [TESTING_COMPLETE_SYSTEM.md](TESTING_COMPLETE_SYSTEM.md) for:
- JWT token requests
- WebSocket ticket generation
- WebSocket message testing
- Load testing scenarios

## 🔒 Security Features

### Authentication
- ✅ JWT tokens (HS256 with secret)
- ✅ Secure password hashing (Argon2)
- ✅ Password reset tokens (single-use)
- ✅ Rate limiting (10 requests/15 min per IP)

### WebSocket
- ✅ Short-lived tickets (60 seconds)
- ✅ Single-use enforcement
- ✅ Permission validation
- ✅ No sensitive data in URLs
- ✅ House-bound sessions

### Database
- ✅ D1 SQLite with Cloudflare
- ✅ Prepared statements (SQL injection prevention)
- ✅ Indexed queries for performance
- ✅ Automatic backups

## 🛠️ Available Commands

```bash
npm run dev              # Start development server
npm run build            # Build for production
npm run deploy           # Deploy to Cloudflare
npm test                 # Run test suite
npm run device:sim       # Run IoT device simulator
```

## 🔧 Configuration

### Environment Variables

```bash
# In .env file
JWT_SCRT=your_jwt_secret_here
```

### Cloudflare Secrets

Store production secrets in Cloudflare:
```bash
wrangler secret put JWT_SCRT
```

## 📊 Database Schema

### Core Tables
- `users` - User accounts
- `tenants` - Property tenant records
- `refresh_tokens` - Session tokens
- `password_resets` - Reset token storage

### Smart Home Tables (NEW!)
- `houses` - Property/house records
- `devices` - IoT device registry
- `user_house_access` - Permission mappings
- `websocket_tickets` - Ticket lifecycle

## 🚀 Deployment

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm run deploy
```

See [06-DEPLOYMENT.md](docs/06-DEPLOYMENT.md) for detailed steps.

## 🤝 Contributing

See [07-CONTRIBUTING.md](docs/07-CONTRIBUTING.md) for:
- Code style guidelines
- Testing requirements
- PR process
- Release procedures

## 📝 What's New

### Version 2.0.0 (Smart Home Release)

Added complete real-time WebSocket infrastructure:
- ✅ Per-house Durable Objects
- ✅ Secure ticket-based authentication
- ✅ Device command routing
- ✅ Real-time status updates
- ✅ Session management
- ✅ Frontend dashboard
- ✅ Device simulator
- ✅ Comprehensive documentation

See [WEBSOCKET_INTEGRATION_SUMMARY.md](WEBSOCKET_INTEGRATION_SUMMARY.md) for details.

## 📞 Support

### Common Questions

**Q: How do I add more devices?**  
A: Insert into the `devices` table. See [04-DATABASE.md](docs/04-DATABASE.md).

**Q: Can I use real IoT devices (ESP32)?**  
A: Yes! See [09-WEBSOCKET_SETUP.md](docs/09-WEBSOCKET_SETUP.md) for device authentication options.

**Q: Is this production-ready?**  
A: Yes, but customize the permission model and device types for your use case. See integration guide.

**Q: How do I test without IoT devices?**  
A: Use the device simulator: `npm run device:sim`. Fully functional testing without hardware.

### Getting Help

1. **Read the docs** - Start with [01-GETTING_STARTED.md](docs/01-GETTING_STARTED.md)
2. **Run tests** - Follow [TESTING_COMPLETE_SYSTEM.md](TESTING_COMPLETE_SYSTEM.md)
3. **Check examples** - See example code in documentation
4. **Review logs** - Use `wrangler tail` for debugging

## 📄 License

Property of rental management system

## ✨ Key Features Summary

| Feature | Status | Details |
|---------|--------|---------|
| User Authentication | ✅ | JWT with Argon2 hashing |
| Tenant Management | ✅ | Full CRUD operations |
| Password Reset | ✅ | Secure token system |
| WebSocket Rooms | ✅ | Per-house Durable Objects |
| Device Commands | ✅ | Real-time message routing |
| Status Updates | ✅ | Broadcast to all clients |
| Session Management | ✅ | Authenticated tracking |
| Frontend Dashboard | ✅ | Modern React-free UI |
| Device Simulator | ✅ | Node.js test tool |
| API Documentation | ✅ | Complete with examples |
| Deployment Guide | ✅ | Production ready |

---

**Ready to manage your rental properties with real-time smart home control!** 🏠✨

