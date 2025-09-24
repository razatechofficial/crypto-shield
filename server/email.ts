import crypto from 'crypto';

export interface EmailService {
  sendVerificationEmail(email: string, token: string): Promise<void>;
  sendPasswordResetEmail(email: string, token: string): Promise<void>;
}

// Simple console-based email service for development
class ConsoleEmailService implements EmailService {
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/verify-email?token=${token}`;
    
    console.log('\n=== EMAIL VERIFICATION ===');
    console.log(`To: ${email}`);
    console.log(`Subject: Verify Your CryptoShield KMS Account`);
    console.log(`\nVerification Link: ${verificationUrl}`);
    console.log('\nEmail Body:');
    console.log(`Welcome to CryptoShield KMS!
    
Please verify your email address by clicking the link below:
${verificationUrl}

This link will expire in 24 hours for security purposes.

If you didn't create this account, please ignore this email.

Thank you,
The CryptoShield KMS Team`);
    console.log('========================\n');
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/reset-password?token=${token}`;
    
    console.log('\n=== PASSWORD RESET ===');
    console.log(`To: ${email}`);
    console.log(`Subject: Reset Your CryptoShield KMS Password`);
    console.log(`\nReset Link: ${resetUrl}`);
    console.log('\nEmail Body:');
    console.log(`You requested a password reset for your CryptoShield KMS account.

Click the link below to reset your password:
${resetUrl}

This link will expire in 1 hour for security purposes.

If you didn't request this reset, please ignore this email.

Thank you,
The CryptoShield KMS Team`);
    console.log('=====================\n');
  }
}

// Production email service would integrate with services like SendGrid, AWS SES, etc.
class ProductionEmailService implements EmailService {
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    // For now, fall back to console logging in production
    // In a real production environment, this would use a service like:
    // - SendGrid
    // - AWS SES
    // - Twilio SendGrid
    // - Postmark
    // - Mailgun
    
    const consoleService = new ConsoleEmailService();
    await consoleService.sendVerificationEmail(email, token);
    
    // TODO: Replace with actual email service integration
    console.warn('PRODUCTION: Using console email service. Configure a real email service!');
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const consoleService = new ConsoleEmailService();
    await consoleService.sendPasswordResetEmail(email, token);
    
    console.warn('PRODUCTION: Using console email service. Configure a real email service!');
  }
}

// Email service factory
export function createEmailService(): EmailService {
  const env = process.env.NODE_ENV;
  
  if (env === 'production') {
    return new ProductionEmailService();
  } else {
    return new ConsoleEmailService();
  }
}

// Token generation utilities
export function generateVerificationToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Email validation utility
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Create singleton instance
export const emailService = createEmailService();