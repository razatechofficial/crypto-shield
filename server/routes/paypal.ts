import { Router } from 'express';
import { paypalService } from '../services/paypal';
import { storage } from '../storage';
import { enterpriseAuth, requirePermission } from '../middleware/index';

const router = Router();

/**
 * CRYPTOSHIELD KMS PAYPAL BILLING ROUTES
 * PayPal subscription billing endpoints for enterprise Key Management Service
 */

/**
 * POST /api/paypal/checkout
 * Create PayPal subscription checkout session
 */
router.post('/checkout', [...enterpriseAuth, requirePermission('org:billing')], async (req, res) => {
  try {
    const { planId, successUrl, cancelUrl } = req.body;
    const tenantId = req.user!.tenantId;

    if (!planId || !successUrl || !cancelUrl) {
      return res.status(400).json({ 
        error: 'Missing required fields: planId, successUrl, cancelUrl' 
      });
    }

    // Check if tenant already has an active subscription
    const existingSubscription = await storage.getTenantSubscription(tenantId);
    if (existingSubscription && existingSubscription.status === 'active') {
      return res.status(400).json({
        error: 'Tenant already has an active subscription. Please cancel the current subscription before subscribing to a new plan.'
      });
    }

    const checkoutSession = await paypalService.createCheckoutSession(
      tenantId,
      planId,
      successUrl,
      cancelUrl
    );

    res.json(checkoutSession);
  } catch (error: any) {
    console.error('PayPal checkout error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/paypal/verify-subscription
 * Verify PayPal subscription after user approval
 */
router.post('/verify-subscription', adminOnly, async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    
    if (!subscriptionId) {
      return res.status(400).json({ 
        error: 'Missing subscriptionId' 
      });
    }

    const verification = await paypalService.verifySubscription(subscriptionId);
    
    if (!verification.isActive) {
      return res.status(400).json({
        error: `Subscription is not active: ${verification.status}`
      });
    }

    // Handle successful verification (this would typically be done via webhook)
    await paypalService.handleSubscriptionActivated(subscriptionId);

    res.json({
      success: true,
      subscriptionId,
      status: verification.status,
      email: verification.email
    });
  } catch (error: any) {
    console.error('PayPal verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/paypal/subscription-status/:subscriptionId
 * Check PayPal subscription status
 */
router.get('/subscription-status/:subscriptionId', requirePermission('billing:read'), async (req, res) => {
  try {
    const { subscriptionId } = req.params;
    const verification = await paypalService.verifySubscription(subscriptionId);
    
    res.json(verification);
  } catch (error: any) {
    console.error('PayPal status check error:', error);
    res.status(500).json({ error: error.message });
  }
});

export { router as paypalRoutes };