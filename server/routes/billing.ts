import type { Express } from 'express';
import { stripeService } from '../services/stripe';
import { storage } from '../storage';
import { adminOnly, enterpriseAuth, requirePermission } from '../middleware/index';

/**
 * CRYPTOSHIELD KMS BILLING ROUTES
 * Enterprise subscription management with Stripe integration
 */
export function setupBillingRoutes(app: Express) {

  // ====== SUBSCRIPTION MANAGEMENT ROUTES ======

  // Get subscription plans (All authenticated users)
  app.get('/api/billing/plans', enterpriseAuth, async (req, res) => {
    try {
      const plans = await storage.getSubscriptionPlans();
      
      // Filter out plans that don't have Stripe integration
      const activePlans = plans.filter(plan => 
        plan.isActive && plan.stripeProductId && plan.stripePriceId
      );
      
      res.json(activePlans);
    } catch (error: any) {
      console.error('Error fetching subscription plans:', error);
      res.status(500).json({ error: 'Failed to fetch subscription plans' });
    }
  });

  // Get current tenant subscription (All authenticated users)
  app.get('/api/billing/subscription', enterpriseAuth, async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const subscription = await storage.getTenantSubscription(tenantId);
      
      if (!subscription) {
        return res.json({ subscription: null });
      }

      // Get plan details
      const plan = await storage.getSubscriptionPlan(subscription.planId);
      
      res.json({
        subscription: {
          ...subscription,
          plan: plan
        }
      });
    } catch (error: any) {
      console.error('Error fetching tenant subscription:', error);
      res.status(500).json({ error: 'Failed to fetch subscription' });
    }
  });

  // Create checkout session for new subscription (Admin only)
  app.post('/api/billing/checkout', [
    ...enterpriseAuth,
    requirePermission('org:billing')
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const { planId, successUrl, cancelUrl } = req.body;

      if (!planId || !successUrl || !cancelUrl) {
        return res.status(400).json({ 
          error: 'Plan ID, success URL, and cancel URL are required' 
        });
      }

      // Check if tenant already has an active subscription
      const existingSubscription = await storage.getTenantSubscription(tenantId);
      if (existingSubscription && existingSubscription.status === 'active') {
        return res.status(409).json({ 
          error: 'Tenant already has an active subscription. Use the customer portal to make changes.' 
        });
      }

      const session = await stripeService.createCheckoutSession(
        tenantId,
        planId,
        successUrl,
        cancelUrl
      );

      res.json({ checkoutUrl: session.url });
    } catch (error: any) {
      console.error('Error creating checkout session:', error);
      res.status(500).json({ error: error.message || 'Failed to create checkout session' });
    }
  });

  // Create customer portal session (Admin only)
  app.post('/api/billing/portal', [
    ...enterpriseAuth,
    requirePermission('org:billing')
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const { returnUrl } = req.body;

      if (!returnUrl) {
        return res.status(400).json({ error: 'Return URL is required' });
      }

      const session = await stripeService.createPortalSession(tenantId, returnUrl);
      
      res.json({ portalUrl: session.url });
    } catch (error: any) {
      console.error('Error creating portal session:', error);
      res.status(500).json({ error: error.message || 'Failed to create portal session' });
    }
  });

  // ====== BILLING HISTORY ROUTES ======

  // Get payment history (Admin or billing permission)
  app.get('/api/billing/history', [
    ...enterpriseAuth,
    requirePermission('billing:view')
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const limit = parseInt(req.query.limit as string) || 50;
      
      const paymentEvents = await storage.getPaymentHistory(tenantId, limit);
      
      res.json(paymentEvents);
    } catch (error: any) {
      console.error('Error fetching payment history:', error);
      res.status(500).json({ error: 'Failed to fetch payment history' });
    }
  });

  // Get invoices (Admin or billing permission)
  app.get('/api/billing/invoices', [
    ...enterpriseAuth,
    requirePermission('billing:view')
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const limit = parseInt(req.query.limit as string) || 20;
      
      const invoices = await storage.getInvoices(tenantId, limit);
      
      res.json(invoices);
    } catch (error: any) {
      console.error('Error fetching invoices:', error);
      res.status(500).json({ error: 'Failed to fetch invoices' });
    }
  });

  // ====== SUBSCRIPTION STATS ROUTES ======

  // Get billing analytics (Admin only)
  app.get('/api/billing/analytics', adminOnly, async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      
      const subscription = await storage.getTenantSubscription(tenantId);
      const paymentHistory = await storage.getPaymentHistory(tenantId, 12); // Last 12 payments
      
      // Calculate analytics
      const totalSpent = paymentHistory
        .filter(event => event.eventType === 'invoice_paid' && event.status === 'completed')
        .reduce((sum, event) => sum + (event.amount || 0), 0);
      
      const failedPayments = paymentHistory
        .filter(event => event.eventType === 'payment_failed').length;
      
      const successfulPayments = paymentHistory
        .filter(event => event.eventType === 'invoice_paid' && event.status === 'completed').length;
      
      // Calculate next billing date
      const nextBillingDate = subscription?.currentPeriodEnd || null;
      
      res.json({
        subscription: subscription,
        analytics: {
          totalSpent: totalSpent,
          successfulPayments: successfulPayments,
          failedPayments: failedPayments,
          nextBillingDate: nextBillingDate,
          paymentSuccessRate: successfulPayments > 0 ? 
            ((successfulPayments / (successfulPayments + failedPayments)) * 100).toFixed(1) : '100.0'
        },
        recentPayments: paymentHistory.slice(0, 5)
      });
    } catch (error: any) {
      console.error('Error fetching billing analytics:', error);
      res.status(500).json({ error: 'Failed to fetch billing analytics' });
    }
  });
}