import Stripe from 'stripe';
import { storage } from '../storage';

// Initialize Stripe client with TypeScript support (development safe)
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_development_fallback', {
  apiVersion: '2024-06-20',
  typescript: true,
});

/**
 * CRYPTOSHIELD KMS STRIPE SERVICE
 * Enterprise-grade subscription billing for Key Management Service
 */
export class StripeService {
  
  /**
   * Create Stripe checkout session for subscription
   */
  async createCheckoutSession(
    tenantId: string,
    planId: string,
    successUrl: string,
    cancelUrl: string
  ): Promise<{ url: string }> {
    // Check if Stripe is properly configured
    if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith('sk_test_development')) {
      throw new Error('Stripe is not configured for production use. Please set STRIPE_SECRET_KEY environment variable.');
    }

    // Validate success/cancel URLs to prevent open redirect attacks
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
      if (!plan || !plan.stripePriceId) {
        throw new Error('Invalid subscription plan or missing Stripe price ID');
      }

      // Get or create Stripe customer for tenant
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        throw new Error('Tenant not found');
      }

      let customerId: string | undefined;
      
      // Check if tenant already has a Stripe customer
      const existingSubscription = await storage.getTenantSubscription(tenantId);
      if (existingSubscription?.provider === 'stripe') {
        customerId = existingSubscription.customerId;
      } else {
        // Create new Stripe customer
        const customer = await stripe.customers.create({
          name: tenant.name,
          metadata: {
            tenantId: tenantId,
            plan: plan.name,
          }
        });
        customerId = customer.id;
      }

      // Create checkout session
      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        line_items: [{
          price: plan.stripePriceId,
          quantity: 1,
        }],
        mode: 'subscription',
        subscription_data: {
          metadata: {
            tenantId: tenantId,
            planId: planId,
          }
        },
        customer_update: {
          name: 'auto',
          address: 'auto'
        },
        automatic_tax: { enabled: true },
        success_url: successUrl,
        cancel_url: cancelUrl,
      });

      if (!session.url) {
        throw new Error('Failed to create checkout session URL');
      }

      return { url: session.url };
    } catch (error: any) {
      console.error('Error creating checkout session:', error);
      throw new Error(`Failed to create checkout session: ${error.message}`);
    }
  }

  /**
   * Create customer portal session for subscription management
   */
  async createPortalSession(
    tenantId: string,
    returnUrl: string
  ): Promise<{ url: string }> {
    try {
      // Validate return URL to prevent open redirect attacks (same as checkout)
      const allowedOrigins = [
        'http://localhost:5000',
        'https://crypto.averox.com',
        ...(process.env.ALLOWED_REDIRECT_ORIGINS?.split(',') || [])
      ].filter(Boolean);
      
      const returnOrigin = new URL(returnUrl).origin;
      
      if (!allowedOrigins.includes(returnOrigin)) {
        throw new Error('Invalid return URL - must use exact allowed origins');
      }

      // Require HTTPS in production
      if (process.env.NODE_ENV === 'production') {
        if (!returnUrl.startsWith('https://')) {
          throw new Error('HTTPS required for return URL in production');
        }
      }

      const subscription = await storage.getTenantSubscription(tenantId);
      if (!subscription || subscription.provider !== 'stripe') {
        throw new Error('No active Stripe subscription found');
      }

      const session = await stripe.billingPortal.sessions.create({
        customer: subscription.customerId,
        return_url: returnUrl,
      });

      return { url: session.url };
    } catch (error: any) {
      console.error('Error creating portal session:', error);
      throw new Error(`Failed to create portal session: ${error.message}`);
    }
  }

  /**
   * Handle successful checkout session
   */
  async handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
    try {
      const subscriptionId = session.subscription as string;
      const customerId = session.customer as string;

      if (!subscriptionId || !customerId) {
        throw new Error('Missing subscription or customer ID in checkout session');
      }

      // Check if subscription already exists to prevent duplicates
      const existingSubscription = await storage.getTenantSubscriptionByStripeId(subscriptionId);
      if (existingSubscription) {
        console.log(`✅ Subscription ${subscriptionId} already processed, skipping`);
        return;
      }

      // Retrieve subscription details from Stripe to get metadata
      const stripeSubscription = await stripe.subscriptions.retrieve(subscriptionId);
      const { tenantId, planId } = stripeSubscription.metadata!;

      if (!tenantId || !planId) {
        throw new Error('Missing required metadata in subscription');
      }

      // Create or update tenant subscription in database (upsert)
      const dbSubscription = await storage.createTenantSubscription({
        tenantId: tenantId,
        planId: planId,
        provider: 'stripe',
        customerId: customerId,
        subscriptionId: subscriptionId,
        status: stripeSubscription.status === 'active' ? 'active' : 
                stripeSubscription.status === 'trialing' ? 'trialing' : 'pending',
        currentPeriodStart: new Date(stripeSubscription.current_period_start * 1000),
        currentPeriodEnd: new Date(stripeSubscription.current_period_end * 1000),
        trialEnd: stripeSubscription.trial_end ? new Date(stripeSubscription.trial_end * 1000) : undefined,
      });

      // Log successful subscription creation
      await storage.recordPaymentEvent({
        subscriptionId: dbSubscription.id, // Use database subscription ID
        provider: 'stripe',
        eventType: 'checkout_completed',
        status: 'completed',
        amount: stripeSubscription.items.data[0]?.price?.unit_amount || 0,
        currency: stripeSubscription.items.data[0]?.price?.currency || 'usd',
        metadata: { stripeSubscriptionId: subscriptionId },
      });

      console.log(`✅ Subscription created successfully for tenant ${tenantId}`);
    } catch (error: any) {
      console.error('Error handling checkout completed:', error);
      throw error;
    }
  }

  /**
   * Handle subscription status changes
   */
  async handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
    try {
      const tenantId = subscription.metadata?.tenantId;
      if (!tenantId) {
        console.warn('No tenantId in subscription metadata');
        return;
      }

      // Map Stripe status to our status
      let status: 'active' | 'trialing' | 'pending' | 'cancelled' | 'past_due' | 'unpaid';
      switch (subscription.status) {
        case 'active':
          status = 'active';
          break;
        case 'trialing':
          status = 'trialing';
          break;
        case 'past_due':
          status = 'past_due';
          break;
        case 'canceled':
          status = 'cancelled';
          break;
        case 'unpaid':
          status = 'unpaid';
          break;
        default:
          status = 'pending';
      }

      // Update subscription in database
      await storage.updateTenantSubscriptionStatus(tenantId, {
        status: status,
        currentPeriodStart: new Date(subscription.current_period_start * 1000),
        currentPeriodEnd: new Date(subscription.current_period_end * 1000),
        trialEnd: subscription.trial_end ? new Date(subscription.trial_end * 1000) : null,
      });

      // Get database subscription for payment event logging
      const dbSubscription = await storage.getTenantSubscription(tenantId);
      if (dbSubscription) {
        // Log status change event
        await storage.recordPaymentEvent({
          subscriptionId: dbSubscription.id, // Use database subscription ID
          provider: 'stripe',
          eventType: 'subscription_updated',
          status: 'completed',
          amount: subscription.items.data[0]?.price?.unit_amount || 0,
          currency: subscription.items.data[0]?.price?.currency || 'usd',
          metadata: { 
            stripeSubscriptionId: subscription.id,
            oldStatus: subscription.status,
            newStatus: status 
          },
        });
      }

      console.log(`✅ Subscription updated for tenant ${tenantId}: ${status}`);
    } catch (error: any) {
      console.error('Error handling subscription updated:', error);
      throw error;
    }
  }

  /**
   * Handle subscription deletion/cancellation
   */
  async handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
    try {
      const tenantId = subscription.metadata?.tenantId;
      if (!tenantId) {
        console.warn('No tenantId in subscription metadata');
        return;
      }

      // Update subscription status to cancelled
      await storage.updateTenantSubscriptionStatus(tenantId, {
        status: 'cancelled',
        cancelledAt: new Date(),
      });

      // Get database subscription for payment event logging
      const dbSubscription = await storage.getTenantSubscription(tenantId);
      if (dbSubscription) {
        // Log cancellation event
        await storage.recordPaymentEvent({
          subscriptionId: dbSubscription.id, // Use database subscription ID
          provider: 'stripe',
          eventType: 'subscription_cancelled',
          status: 'completed',
          amount: 0,
          currency: subscription.items.data[0]?.price?.currency || 'usd',
          metadata: { stripeSubscriptionId: subscription.id },
        });
      }

      console.log(`✅ Subscription cancelled for tenant ${tenantId}`);
    } catch (error: any) {
      console.error('Error handling subscription deleted:', error);
      throw error;
    }
  }

  /**
   * Handle invoice payment success
   */
  async handleInvoicePaid(invoice: Stripe.Invoice): Promise<void> {
    try {
      const subscriptionId = invoice.subscription as string;
      if (!subscriptionId) return;

      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      const tenantId = subscription.metadata?.tenantId;
      if (!tenantId) return;

      // Get database subscription for payment event logging
      const dbSubscription = await storage.getTenantSubscription(tenantId);
      if (dbSubscription) {
        // Log successful payment
        await storage.recordPaymentEvent({
          subscriptionId: dbSubscription.id, // Use database subscription ID
          provider: 'stripe',
          eventType: 'invoice_paid',
          status: 'completed',
          amount: invoice.amount_paid,
          currency: invoice.currency,
          metadata: {
            stripeInvoiceId: invoice.id,
            stripeSubscriptionId: subscriptionId,
            billingReason: invoice.billing_reason || undefined,
          },
        });
      }

      console.log(`✅ Invoice paid for tenant ${tenantId}: $${(invoice.amount_paid / 100).toFixed(2)} ${invoice.currency.toUpperCase()}`);
    } catch (error: any) {
      console.error('Error handling invoice paid:', error);
    }
  }

  /**
   * Handle invoice payment failure
   */
  async handleInvoicePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
    try {
      const subscriptionId = invoice.subscription as string;
      if (!subscriptionId) return;

      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      const tenantId = subscription.metadata?.tenantId;
      if (!tenantId) return;

      // Get database subscription for payment event logging
      const dbSubscription = await storage.getTenantSubscription(tenantId);
      if (dbSubscription) {
        // Log failed payment
        await storage.recordPaymentEvent({
          subscriptionId: dbSubscription.id, // Use database subscription ID
          provider: 'stripe',
          eventType: 'payment_failed',
          status: 'failed',
          amount: invoice.amount_due,
          currency: invoice.currency,
          metadata: {
            stripeInvoiceId: invoice.id,
            stripeSubscriptionId: subscriptionId,
            failureReason: 'payment_failed',
          },
        });
      }

      // Update subscription status if needed
      if (subscription.status === 'past_due') {
        await storage.updateTenantSubscriptionStatus(tenantId, {
          status: 'past_due',
        });
      }

      console.log(`❌ Invoice payment failed for tenant ${tenantId}: $${(invoice.amount_due / 100).toFixed(2)} ${invoice.currency.toUpperCase()}`);
    } catch (error: any) {
      console.error('Error handling invoice payment failed:', error);
    }
  }
}

export const stripeService = new StripeService();