import crypto from 'crypto';
import nodemailer from 'nodemailer';

export interface EmailService {
  sendVerificationEmail(email: string, token: string): Promise<void>;
  sendPasswordResetEmail(email: string, token: string): Promise<void>;
  sendTrialWelcomeEmail(email: string, firstName: string, companyName: string, token: string): Promise<void>;
}

// Production SMTP email service using nodemailer
class SMTPEmailService implements EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: parseInt(process.env.SMTP_PORT || '587') === 465, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USERNAME,
        pass: process.env.SMTP_PASSWORD,
      },
    });
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/verify-email?token=${token}`;
    
    const mailOptions = {
      from: process.env.SMTP_FROM_EMAIL,
      to: email,
      subject: 'Verify Your CryptoShield KMS Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2563eb;">Welcome to CryptoShield KMS!</h2>
          
          <p>Thank you for creating your account. To complete your registration and secure your access to our enterprise-grade encryption platform, please verify your email address.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="color: #666; font-size: 14px; word-break: break-all;">${verificationUrl}</p>
          
          <p style="color: #666; font-size: 14px;">This verification link will expire in 24 hours for security purposes.</p>
          
          <p style="color: #666; font-size: 14px;">If you didn't create this account, please ignore this email.</p>
          
          <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #666; font-size: 12px;">
            This email was sent from CryptoShield KMS - Enterprise Encryption Platform<br>
            For support, please contact your system administrator.
          </p>
        </div>
      `,
      text: `Welcome to CryptoShield KMS!
      
Please verify your email address by clicking the link below:
${verificationUrl}

This link will expire in 24 hours for security purposes.

If you didn't create this account, please ignore this email.

Thank you,
The CryptoShield KMS Team`
    };

    await this.transporter.sendMail(mailOptions);
    console.log(`✅ Verification email sent to ${email}`);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/reset-password?token=${token}`;
    
    const mailOptions = {
      from: process.env.SMTP_FROM_EMAIL,
      to: email,
      subject: 'Reset Your CryptoShield KMS Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #dc2626;">Password Reset Request</h2>
          
          <p>You requested a password reset for your CryptoShield KMS account.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="color: #666; font-size: 14px; word-break: break-all;">${resetUrl}</p>
          
          <p style="color: #666; font-size: 14px;">This reset link will expire in 1 hour for security purposes.</p>
          
          <p style="color: #666; font-size: 14px;">If you didn't request this reset, please ignore this email and your password will remain unchanged.</p>
          
          <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #666; font-size: 12px;">
            This email was sent from CryptoShield KMS - Enterprise Encryption Platform<br>
            For support, please contact your system administrator.
          </p>
        </div>
      `,
      text: `You requested a password reset for your CryptoShield KMS account.

Click the link below to reset your password:
${resetUrl}

This link will expire in 1 hour for security purposes.

If you didn't request this reset, please ignore this email.

Thank you,
The CryptoShield KMS Team`
    };

    await this.transporter.sendMail(mailOptions);
    console.log(`✅ Password reset email sent to ${email}`);
  }

  async sendTrialWelcomeEmail(email: string, firstName: string, companyName: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/verify-email?token=${token}`;
    
    const mailOptions = {
      from: process.env.SMTP_FROM_EMAIL,
      to: email,
      subject: `Welcome to CryptoShield KMS - Your 14-Day Trial Starts Now!`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2563eb;">🎉 Welcome to CryptoShield KMS, ${firstName}!</h2>
          
          <p>Congratulations! Your 14-day free trial for ${companyName} has been activated.</p>
          
          <div style="background-color: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 6px; padding: 20px; margin: 20px 0;">
            <h3 style="color: #0c4a6e; margin: 0 0 10px 0;">🚀 Your Trial Includes:</h3>
            <ul style="color: #0c4a6e; margin: 0; padding-left: 20px;">
              <li>Full access to enterprise-grade encryption APIs</li>
              <li>Multi-cloud key management (AWS, Azure, GCP)</li>
              <li>Quantum-safe cryptographic algorithms</li>
              <li>Real-time security monitoring</li>
              <li>Custom SDK generation in 13+ languages</li>
              <li>Complete compliance reporting (FIPS 140-3, NIST)</li>
            </ul>
          </div>
          
          <p style="font-size: 16px; font-weight: 600;">To access your dashboard, please verify your email address:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #2563eb; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 600;">
              Verify Email & Start Trial
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">If the button doesn't work, copy and paste this link:</p>
          <p style="color: #666; font-size: 14px; word-break: break-all;">${verificationUrl}</p>
          
          <div style="background-color: #fffbeb; border: 1px solid #f59e0b; border-radius: 6px; padding: 15px; margin: 25px 0;">
            <p style="color: #92400e; margin: 0; font-size: 14px;">
              ⏰ <strong>Trial expires in 14 days</strong> - No credit card required during trial period.
            </p>
          </div>
          
          <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #666; font-size: 12px;">
            Questions? Reply to this email or contact our technical team.<br>
            CryptoShield KMS - Enterprise Encryption Platform
          </p>
        </div>
      `,
      text: `Welcome to CryptoShield KMS, ${firstName}!

Your 14-day free trial for ${companyName} has been activated.

Trial includes:
- Full access to enterprise-grade encryption APIs
- Multi-cloud key management (AWS, Azure, GCP)  
- Quantum-safe cryptographic algorithms
- Real-time security monitoring
- Custom SDK generation in 13+ languages
- Complete compliance reporting (FIPS 140-3, NIST)

To access your dashboard, verify your email: ${verificationUrl}

This verification link expires in 24 hours.
Trial expires in 14 days - No credit card required.

Questions? Reply to this email or contact our technical team.
CryptoShield KMS Team`
    };

    await this.transporter.sendMail(mailOptions);
    console.log(`✅ Trial welcome email sent to ${email} for ${companyName}`);
  }
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

  async sendTrialWelcomeEmail(email: string, firstName: string, companyName: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.BASE_URL || 'http://localhost:5000'}/verify-email?token=${token}`;
    
    console.log('\n=== TRIAL WELCOME EMAIL ===');
    console.log(`To: ${email}`);
    console.log(`Subject: Welcome to CryptoShield KMS - Your 14-Day Trial Starts Now!`);
    console.log(`\nVerification Link: ${verificationUrl}`);
    console.log('\nEmail Body:');
    console.log(`🎉 Welcome to CryptoShield KMS, ${firstName}!

Congratulations! Your 14-day free trial for ${companyName} has been activated.

Your Trial Includes:
• Full access to enterprise-grade encryption APIs
• Multi-cloud key management (AWS, Azure, GCP)
• Quantum-safe cryptographic algorithms  
• Real-time security monitoring
• Custom SDK generation in 13+ languages
• Complete compliance reporting (FIPS 140-3, NIST)

To access your dashboard, please verify your email address:
${verificationUrl}

This verification link expires in 24 hours.
Trial expires in 14 days - No credit card required.

Questions? Reply to this email or contact our technical team.

Thank you,
The CryptoShield KMS Team`);
    console.log('==========================\n');
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

  async sendTrialWelcomeEmail(email: string, firstName: string, companyName: string, token: string): Promise<void> {
    const consoleService = new ConsoleEmailService();
    await consoleService.sendTrialWelcomeEmail(email, firstName, companyName, token);
    
    console.warn('PRODUCTION: Using console email service. Configure a real email service!');
  }
}

// Email service factory
export function createEmailService(): EmailService {
  // In development, always use console service to avoid SMTP issues
  if (process.env.NODE_ENV === 'development') {
    console.log('📧 Development mode: Using console email service');
    return new ConsoleEmailService();
  }
  
  // Check if SMTP credentials are available
  if (process.env.SMTP_HOST && process.env.SMTP_USERNAME && process.env.SMTP_PASSWORD) {
    return new SMTPEmailService();
  } else {
    console.log('📧 No SMTP credentials found, using console email service for development');
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