import axios, { AxiosRequestConfig } from 'axios';
import { storage } from '../storage';

/**
 * CRYPTOSHIELD KMS PAYPAL SERVICE
 * Enterprise-grade PayPal subscription billing for Key Management Service
 * Direct HTTP integration (official SDK deprecated)
 */
export class PayPalService {
  private baseURL: string;

  constructor() {
    // Use sandbox in development, production in production
    this.baseURL = process.env.NODE_ENV === 'production' 
      ? 'https://api-m.paypal.com'
      : 'https://api-m.sandbox.paypal.com';
  }

  /**
   * Get PayPal access token for API authentication
   */
  private async getAccessToken(): Promise<string> {
    // Check if PayPal is properly configured
    if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
      throw new Error('PayPal is not configured. Please set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET environment variables.');
    }

    try {
      const config: AxiosRequestConfig = {
        method: 'POST',
        url: `${this.baseURL}/v1/oauth2/token`,
        headers: {
          'Accept': 'application/json',
          'Accept-Language': 'en_US',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        auth: {
          username: process.env.PAYPAL_CLIENT_ID,
          password: process.env.PAYPAL_CLIENT_SECRET,
        },
        data: 'grant_type=client_credentials',
      };

      const response = await axios(config);
      return response.data.access_token;
    } catch (error: any) {
      console.error('Error getting PayPal access token:', error.response?.data || error.message);
      throw new Error(`Failed to get PayPal access token: ${error.message}`);
    }
  }

  /**
   * Create or update PayPal product for subscription plans
   */
  private async ensureProduct(tenantId: string): Promise<string> {
    const accessToken = await this.getAccessToken();

    try {
      // Check if tenant already has a PayPal product ID
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        throw new Error('Tenant not found');
      }

      // For now, use a single product for all subscriptions
      // In production, you might want tenant-specific products
      const productData = {
        name: 'CryptoShield KMS Enterprise Subscription',
        description: 'Enterprise-grade Key Management Service subscription',
        type: 'SERVICE',
        category: 'SOFTWARE',
      };

      const config: AxiosRequestConfig = {
        method: 'POST',
        url: `${this.baseURL}/v1/catalogs/products`,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'PayPal-Request-Id': `cryptoshield-product-${Date.now()}`,
        },
        data: productData,
      };

      const response = await axios(config);
      return response.data.id;
    } catch (error: any) {
      // If product already exists, we can reuse it
      if (error.response?.status === 400 && error.response?.data?.details?.[0]?.issue === 'DUPLICATE_RESOURCE') {
        console.warn('PayPal product already exists, this is expected for multi-tenant usage');
        // For now, return a fixed product ID - in production, store this properly
        return process.env.PAYPAL_PRODUCT_ID || 'PROD-CRYPTOSHIELD-KMS';
      }
      
      console.error('Error creating PayPal product:', error.response?.data || error.message);
      throw new Error(`Failed to create PayPal product: ${error.message}`);
    }
  }

  /**
   * Create PayPal subscription checkout session
   */
  async createCheckoutSession(
    tenantId: string,
    planId: string,
    successUrl: string,
    cancelUrl: string
  ): Promise<{ url: string }> {
    // Check if PayPal is properly configured
    if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
      console.warn('⚠️ PayPal not configured for production, returning service unavailable');
      throw new Error('Billing service unavailable - PayPal configuration required for payment processing');
    }

    // Validate success/cancel URLs to prevent open redirect attacks (same as Stripe)
    const allowedOrigins = [
      'http://localhost:5000',
      'https://crypto.averox.com',
      ...(process.env.ALLOWED_REDIRECT_ORIGINS?.split(',') || [])
    ].filter(Boolean);
    
    const successOrigin = new URL(successUrl).origin;
    const cancelOrigin = new URL(cancelUrl).origin;
    
    if (!allowedOrigins.includes(successOrigin) || !allowedOrigins.includes(cancelOrigin)) {
      throw new Error('Invalid redirect URLs - must use exact allowed origins');
    }

    // Require HTTPS in production
    if (process.env.NODE_ENV === 'production') {
      if (!successUrl.startsWith('https://') || !cancelUrl.startsWith('https://')) {
        throw new Error('HTTPS required for redirect URLs in production');
      }
    }

    try {
      // Get subscription plan details
      const plan = await storage.getSubscriptionPlan(planId);
      if (!plan || !plan.paypalPlanId) {
        throw new Error('Invalid subscription plan or missing PayPal plan ID');
      }

      const accessToken = await this.getAccessToken();

      // Create subscription
      const subscriptionData = {
        plan_id: plan.paypalPlanId,
        application_context: {
          brand_name: 'CryptoShield KMS',
          locale: 'en-US',
          shipping_preference: 'NO_SHIPPING',
          user_action: 'SUBSCRIBE_NOW',
          payment_method: {
            payer_selected: 'PAYPAL',
            payee_preferred: 'IMMEDIATE_PAYMENT_REQUIRED',
          },
          return_url: successUrl,
          cancel_url: cancelUrl,
        },
        subscriber: {
          name: {
            given_name: 'Enterprise',
            surname: 'User',
          },
        },
      };

      const config: AxiosRequestConfig = {
        method: 'POST',
        url: `${this.baseURL}/v1/billing/subscriptions`,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'PayPal-Request-Id': `cryptoshield-sub-${Date.now()}-${tenantId}`,
        },
        data: subscriptionData,
      };

      const response = await axios(config);
      
      // Find the approval URL
      const approvalUrl = response.data.links?.find(
        (link: any) => link.rel === 'approve'
      )?.href;

      if (!approvalUrl) {
        throw new Error('No approval URL returned from PayPal');
      }

      return { url: approvalUrl };
    } catch (error: any) {
      console.error('Error creating PayPal checkout session:', error.response?.data || error.message);
      throw new Error(`Failed to create PayPal checkout session: ${error.message}`);
    }
  }

  /**
   * Handle successful PayPal subscription activation
   */
  async handleSubscriptionActivated(subscriptionId: string): Promise<void> {
    try {
      const accessToken = await this.getAccessToken();
      
      // Get subscription details from PayPal
      const config: AxiosRequestConfig = {
        method: 'GET',
        url: `${this.baseURL}/v1/billing/subscriptions/${subscriptionId}`,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
        },
      };

      const response = await axios(config);
      const subscription = response.data;

      if (subscription.status !== 'ACTIVE') {
        throw new Error(`Subscription is not active: ${subscription.status}`);
      }

      // Extract tenant ID from custom_id or metadata if available
      const tenantId = subscription.custom_id || 
                     subscription.subscriber?.email_address?.split('@')[0] || // fallback
                     'unknown';

      // Get the plan details
      const planId = subscription.plan_id;
      const plan = await storage.getSubscriptionPlanByPayPalId(planId);
      
      if (!plan) {
        console.error(`No plan found for PayPal plan ID: ${planId}`);
        throw new Error('Plan not found for PayPal subscription');
      }

      // Create or update tenant subscription
      const subscriptionData = {
        tenantId,
        planId: plan.id,
        provider: 'paypal' as const,
        subscriptionId: subscriptionId,
        customerId: subscription.subscriber?.email_address || 'paypal-customer',
        status: 'active' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
        metadata: JSON.stringify({
          paypal_subscription_id: subscriptionId,
          paypal_plan_id: planId,
          subscriber_email: subscription.subscriber?.email_address,
        }),
      };

      await storage.updateTenantSubscriptionStatus(tenantId, subscriptionData);

      console.log(`✅ PayPal subscription activated successfully for tenant ${tenantId}`);
    } catch (error: any) {
      console.error('Error handling PayPal subscription activation:', error);
      throw error;
    }
  }

  /**
   * Handle PayPal subscription cancellation
   */
  async handleSubscriptionCancelled(subscriptionId: string): Promise<void> {
    try {
      // Find the tenant subscription by PayPal subscription ID
      const subscription = await storage.getTenantSubscriptionByPayPalId(subscriptionId);
      
      if (!subscription) {
        console.warn(`No subscription found for PayPal subscription ID: ${subscriptionId}`);
        return;
      }

      // Update subscription status to cancelled
      await storage.updateTenantSubscriptionStatus(subscription.tenantId, {
        ...subscription,
        status: 'cancelled' as const,
        metadata: JSON.stringify({
          ...JSON.parse(subscription.metadata || '{}'),
          cancelled_at: new Date().toISOString(),
          cancellation_reason: 'paypal_subscription_cancelled',
        }),
      });

      console.log(`✅ PayPal subscription cancelled for tenant ${subscription.tenantId}`);
    } catch (error: any) {
      console.error('Error handling PayPal subscription cancellation:', error);
      throw error;
    }
  }

  /**
   * Verify PayPal subscription status
   */
  async verifySubscription(subscriptionId: string): Promise<{
    isActive: boolean;
    status: string;
    email?: string;
  }> {
    try {
      const accessToken = await this.getAccessToken();
      
      const config: AxiosRequestConfig = {
        method: 'GET',
        url: `${this.baseURL}/v1/billing/subscriptions/${subscriptionId}`,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
        },
      };

      const response = await axios(config);
      const subscription = response.data;

      return {
        isActive: subscription.status === 'ACTIVE',
        status: subscription.status,
        email: subscription.subscriber?.email_address,
      };
    } catch (error: any) {
      console.error('Error verifying PayPal subscription:', error.response?.data || error.message);
      return { isActive: false, status: 'error' };
    }
  }
}

// Export singleton instance
export const paypalService = new PayPalService();