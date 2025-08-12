# Overview

Averox is an enterprise-grade encryption platform that enables users to create custom encryption SDKs with quantum-safe algorithms, auto-healing capabilities, and comprehensive monitoring. The platform provides a web-based interface for managing encryption keys, monitoring security events, creating SDKs through a wizard interface, and managing users and subscriptions. The application focuses on providing enterprise-level encryption solutions with real-time monitoring, threat detection, and automated key rotation capabilities.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: React with TypeScript using Vite as the build tool
- **Routing**: Wouter for client-side routing with conditional rendering based on authentication state
- **Styling**: Tailwind CSS with shadcn/ui component library providing a comprehensive set of pre-built UI components
- **State Management**: TanStack Query (React Query) for server state management and caching
- **Authentication Flow**: Conditional rendering between landing page (unauthenticated) and main application (authenticated)
- **Component Structure**: Modular design with reusable components for stats cards, charts, algorithm selectors, and UI elements

## Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **Database Integration**: Drizzle ORM with PostgreSQL via Neon serverless database
- **Authentication**: Replit OIDC authentication with Passport.js and session management
- **Session Storage**: PostgreSQL-based session storage with express-session and connect-pg-simple
- **API Design**: RESTful API endpoints organized by feature domains (auth, dashboard, SDKs, keys, users, monitoring)
- **Development Setup**: Vite middleware integration for development with HMR support

## Database Schema Design
- **User Management**: Users table with role-based permissions (admin, developer, viewer)
- **Multi-tenancy**: Tenant-based architecture with subscription tiers (starter, professional, enterprise)
- **SDK Management**: Support for multiple programming languages (JavaScript, Python, Java, C#, Go, Rust)
- **Encryption System**: Algorithm catalog with quantum-safe and post-quantum options, key lifecycle management
- **Security Monitoring**: Comprehensive event logging and API usage tracking
- **Session Management**: Dedicated sessions table for authentication persistence

## Data Storage Solutions
- **Primary Database**: PostgreSQL via Neon serverless with connection pooling
- **ORM**: Drizzle for type-safe database operations with schema-driven development
- **Migration System**: Drizzle Kit for database migrations and schema management
- **Connection Strategy**: Connection pooling with WebSocket support for serverless environments

## Authentication & Authorization
- **Provider**: Replit OIDC (OpenID Connect) for enterprise authentication
- **Session Management**: Server-side sessions with PostgreSQL storage and configurable TTL
- **Security Features**: HTTPS-only cookies, CSRF protection, session timeout, and failed attempt limiting
- **Authorization Pattern**: Role-based access control with tenant-level data isolation

## File Upload & Storage
- **Cloud Storage**: Google Cloud Storage integration for file uploads
- **Upload Interface**: Uppy.js for drag-and-drop file uploads with progress tracking
- **Storage Strategy**: Multi-provider support with AWS S3 compatibility

# External Dependencies

## Database Services
- **Neon Database**: Serverless PostgreSQL database with automatic scaling
- **Connection Pooling**: Built-in connection pooling for optimal performance

## Authentication Services
- **Replit OIDC**: Enterprise authentication provider with JWT token management
- **OpenID Connect**: Industry-standard authentication protocol implementation

## Cloud Storage
- **Google Cloud Storage**: Primary file storage service for SDK artifacts and user uploads
- **AWS S3 Compatible**: Alternative storage backend support through Uppy.js

## UI Component Libraries
- **shadcn/ui**: Comprehensive component library built on Radix UI primitives
- **Radix UI**: Accessible, unstyled UI component primitives
- **Chart.js**: Data visualization library for security monitoring and analytics dashboards

## Development Tools
- **Replit Integration**: Development environment integration with runtime error overlays and cartographer support
- **Vite Plugins**: Hot module replacement, error handling, and development tooling