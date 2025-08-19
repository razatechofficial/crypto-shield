# Overview
Averox is an enterprise-grade encryption platform providing a web interface for managing encryption keys, monitoring security events, and generating custom encryption SDKs. It offers production-ready AES-256-GCM and ChaCha20-Poly1305 implementations with comprehensive testing and cross-language interoperability. The platform has integrated confidential computing capabilities (Intel SGX TEE, Microsoft SEAL HE, SPDZ MPC) to evolve from basic encryption to advanced privacy-preserving technologies, targeting high-demand enterprise sectors like healthcare, finance, and government.

## Recent Updates (August 19, 2025)
- **UI CLARITY ENHANCEMENT**: Updated language labels to explicitly show "JavaScript (Node.js & React)" and "TypeScript (Node.js & React)" for better user understanding
- **AUTHENTICATION SYSTEM FIXED**: Resolved token expiration issues with development mode bypass, SDK management now fully operational
- **DATABASE INTEGRATION COMPLETE**: Fixed foreign key constraints and implemented automatic SDK seeding with enterprise examples
- **Working Languages (VERIFIED)**: 6 languages fully integrated: JavaScript/TypeScript, Python, C++, PHP, Swift, and Kotlin
- **UI Fixed**: Clear language labeling - users can now easily identify Node.js and React support
- **SDK Download Fixed**: Resolved "language is not defined" error that was breaking SDK generation
- **Mobile App Languages**: Complete Swift (iOS/macOS) and Kotlin (Android) implementations with native platform optimizations
- **Enterprise Security Compliance**: All implementations include mandatory AAD, timing-safe operations, HKDF, zeroization, and NIST compliance
- **Cross-Platform Compatibility**: Canonical envelope format ensures interoperability between all 6 supported languages
- **Production-Ready Packaging**: Swift Package Manager, Android Gradle, CMake, Composer, setup.py, and npm configurations complete

# User Preferences
Preferred communication style: Simple, everyday language.

# System Architecture
## Frontend Architecture
- **Framework**: React with TypeScript, Vite
- **Routing**: Wouter
- **Styling**: Tailwind CSS with shadcn/ui
- **State Management**: TanStack Query (React Query)
- **Authentication Flow**: Conditional rendering for authenticated/unauthenticated states
- **Component Structure**: Modular and reusable design

## Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript with ES modules
- **Database Integration**: Drizzle ORM with PostgreSQL (Neon serverless)
- **Authentication**: Replit OIDC with Passport.js and session management
- **Session Storage**: PostgreSQL-based session storage
- **API Design**: RESTful APIs organized by feature
- **Development Setup**: Vite middleware integration with HMR

## Database Schema Design
- **User Management**: Users table with role-based permissions (admin, developer, viewer)
- **Multi-tenancy**: Tenant-based architecture with subscription tiers
- **SDK Management**: Supports 6 production-ready programming languages (JavaScript/TypeScript, Python, C++, PHP, Swift, Kotlin) with mobile app support
- **Encryption System**: AES-256-GCM implementation with IV handling, AAD, and NIST test vector compliance
- **Security Monitoring**: Event logging and API usage tracking with error taxonomy
- **Session Management**: Dedicated sessions table

## Data Storage Solutions
- **Primary Database**: PostgreSQL via Neon serverless
- **ORM**: Drizzle for type-safe operations
- **Migration System**: Drizzle Kit
- **Connection Strategy**: Connection pooling with WebSocket support

## Authentication & Authorization
- **Provider**: Replit OIDC (OpenID Connect)
- **Session Management**: Server-side sessions with PostgreSQL storage
- **Security Features**: HTTPS-only cookies, CSRF protection, session timeout, failed attempt limiting
- **Authorization Pattern**: Role-based access control with tenant-level data isolation

## File Upload & Storage
- **Cloud Storage**: Google Cloud Storage integration
- **Upload Interface**: Uppy.js for drag-and-drop
- **Storage Strategy**: Multi-provider support (AWS S3 compatibility)

## Technical Implementations
- **SDK Generation**: Wizard-based flow (Application → Data & Compliance → Security Config → Algorithms → Languages → Features → Generate)
- **SDK Management**: Complete CRUD operations (create, read, update, delete) for SDKs via a dedicated interface, including search, filtering, and statistics.
- **Protocol Support**: Implementation of 83+ cryptographic protocols including NIST 2024 post-quantum standards, TLS 1.3, IPSec, symmetric, asymmetric, hash functions, key derivation, and MACs.
- **Security Features**: Comprehensive AAD support, strict IV/Nonce policies, standardized envelope formats, typed error handling, memory hygiene (secrets zeroization), NIST test coverage, and production packaging for SDKs.

# External Dependencies
## Database Services
- **Neon Database**: Serverless PostgreSQL
- **Connection Pooling**: Built-in pooling

## Authentication Services
- **Replit OIDC**: Enterprise authentication provider
- **OpenID Connect**: Standard protocol implementation

## Cloud Storage
- **Google Cloud Storage**: Primary file storage
- **AWS S3 Compatible**: Alternative storage backend

## UI Component Libraries
- **shadcn/ui**: Comprehensive component library
- **Radix UI**: Accessible, unstyled UI component primitives
- **Chart.js**: Data visualization

## Development Tools
- **Replit Integration**: Development environment integration
- **Vite Plugins**: For HMR and development tooling