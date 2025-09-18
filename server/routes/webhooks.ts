import type { Express } from 'express';
import express from 'express';
import { stripe, stripeService } from '../services/stripe';

/**
 * CRYPTOSHIELD KMS STRIPE WEBHOOKS
 * Secure webhook handling for subscription billing events
 */
export function setupWebhookRoutes(app: Express) {

  // Stripe webhook handler - MUST be mounted before JSON middleware
  // IMPORTANT: This must use raw body parsing for signature verification
  app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }));
  
  app.post('/api/webhooks/stripe', async (req, res) => {
      // Validate webhook secret configuration
      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        console.error('❌ STRIPE_WEBHOOK_SECRET not configured');
        return res.status(500).json({ error: 'Webhook not configured' });
      }

      const sig = req.headers['stripe-signature'];
      let event;

      try {
        // Verify webhook signature for security
        event = stripe.webhooks.constructEvent(
          req.body, 
          sig as string, 
          process.env.STRIPE_WEBHOOK_SECRET
        );
      } catch (err: any) {
        console.error(`❌ Webhook signature verification failed: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }

      // Check for duplicate events using event ID
      const eventId = event.id;
      // TODO: Implement event deduplication with database storage
      // For now, log the event ID for manual deduplication if needed
      console.log(`🔔 Processing Stripe event ${eventId}: ${event.type}`);

      console.log(`🔔 Received Stripe webhook: ${event.type}`);

      try {
        // Handle specific webhook events
        switch (event.type) {
          case 'checkout.session.completed':
            console.log('🎯 Processing checkout session completed...');
            await stripeService.handleCheckoutCompleted(event.data.object);
            break;

          case 'customer.subscription.created':
          case 'customer.subscription.updated':
            console.log('🔄 Processing subscription update...');
            await stripeService.handleSubscriptionUpdated(event.data.object);
            break;

          case 'customer.subscription.deleted':
            console.log('❌ Processing subscription cancellation...');
            await stripeService.handleSubscriptionDeleted(event.data.object);
            break;

          case 'invoice.paid':
            console.log('💰 Processing successful payment...');
            await stripeService.handleInvoicePaid(event.data.object);
            break;

          case 'invoice.payment_failed':
            console.log('💳 Processing payment failure...');
            await stripeService.handleInvoicePaymentFailed(event.data.object);
            break;

          case 'customer.subscription.trial_will_end':
            console.log('⏰ Trial ending soon notification...');
            // Could add email notification here
            break;

          default:
            console.log(`ℹ️ Unhandled webhook event type: ${event.type}`);
        }

        // Only return success after successful processing
        res.status(200).json({ received: true });

      } catch (error: any) {
        console.error(`❌ Error processing webhook ${event.type}:`, error);
        
        // Return 500 for transient errors to trigger Stripe retries
        // Return 400 for non-retryable errors (malformed data)
        const isTransientError = error.message?.includes('connection') || 
                                 error.message?.includes('timeout') ||
                                 error.message?.includes('ENOTFOUND');
        
        if (isTransientError) {
          res.status(500).json({ 
            error: 'Transient processing error - will retry',
            event_id: event.id 
          });
        } else {
          res.status(400).json({ 
            error: 'Processing error - will not retry',
            event_id: event.id 
          });
        }
      }
    }
  );
}