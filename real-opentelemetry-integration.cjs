/**
 * Real OpenTelemetry Integration
 * Production-ready OTEL instrumentation with official APIs
 */

let otelAPI = null;
let meterProvider = null;
let tracerProvider = null;

// Try to load OpenTelemetry APIs (graceful fallback)
try {
  otelAPI = require('@opentelemetry/api');
  console.log('[OTEL] OpenTelemetry API loaded successfully');
} catch (error) {
  console.warn('[OTEL] OpenTelemetry API not available - install: npm install @opentelemetry/api @opentelemetry/auto-instrumentations-node');
}

/**
 * Production OpenTelemetry Integration
 * Uses official OTEL APIs with proper meter/tracer providers
 */
class RealOpenTelemetryIntegration {
  static isEnabled = false;
  static meter = null;
  static tracer = null;
  static counters = {};
  static histograms = {};
  
  /**
   * Initialize OpenTelemetry with official APIs
   */
  static initialize() {
    if (!otelAPI) {
      console.warn('[OTEL] OpenTelemetry not available - using fallback telemetry');
      return false;
    }
    
    try {
      // Get meter for metrics
      this.meter = otelAPI.metrics.getMeter('averox-crypto-sdk', '2.0.0');
      
      // Get tracer for distributed tracing  
      this.tracer = otelAPI.trace.getTracer('averox-crypto-sdk', '2.0.0');
      
      // Create metric instruments
      this.counters = {
        encrypt_operations: this.meter.createCounter('averox_encrypt_total', {
          description: 'Total number of encryption operations'
        }),
        decrypt_operations: this.meter.createCounter('averox_decrypt_total', {
          description: 'Total number of decryption operations'
        }),
        auth_failures: this.meter.createCounter('averox_auth_failures_total', {
          description: 'Total number of authentication failures'
        }),
        kdf_operations: this.meter.createCounter('averox_kdf_total', {
          description: 'Total number of key derivation operations'
        })
      };
      
      this.histograms = {
        encrypt_duration: this.meter.createHistogram('averox_encrypt_duration_ms', {
          description: 'Encryption operation duration in milliseconds',
          unit: 'ms'
        }),
        decrypt_duration: this.meter.createHistogram('averox_decrypt_duration_ms', {
          description: 'Decryption operation duration in milliseconds',
          unit: 'ms'
        }),
        kdf_duration: this.meter.createHistogram('averox_kdf_duration_ms', {
          description: 'Key derivation duration in milliseconds',
          unit: 'ms'
        })
      };
      
      this.isEnabled = true;
      console.log('[OTEL] OpenTelemetry instrumentation initialized');
      return true;
    } catch (error) {
      console.error('[OTEL] Failed to initialize OpenTelemetry:', error);
      return false;
    }
  }
  
  /**
   * Record successful encryption with real OTEL metrics
   */
  static recordEncryptSuccess(duration_ms, algorithm = 'AES-256-GCM') {
    if (!this.isEnabled) return;
    
    try {
      // Counter increment
      this.counters.encrypt_operations.add(1, {
        algorithm: algorithm,
        status: 'success'
      });
      
      // Duration histogram
      this.histograms.encrypt_duration.record(duration_ms, {
        algorithm: algorithm
      });
    } catch (error) {
      console.error('[OTEL] Error recording encrypt metrics:', error);
    }
  }
  
  /**
   * Record successful decryption with real OTEL metrics
   */
  static recordDecryptSuccess(duration_ms, algorithm = 'AES-256-GCM') {
    if (!this.isEnabled) return;
    
    try {
      this.counters.decrypt_operations.add(1, {
        algorithm: algorithm,
        status: 'success'
      });
      
      this.histograms.decrypt_duration.record(duration_ms, {
        algorithm: algorithm
      });
    } catch (error) {
      console.error('[OTEL] Error recording decrypt metrics:', error);
    }
  }
  
  /**
   * Record authentication failure with real OTEL metrics
   */
  static recordAuthFailure(error_type = 'auth_failure') {
    if (!this.isEnabled) return;
    
    try {
      this.counters.auth_failures.add(1, {
        error_type: error_type,
        severity: 'warning'
      });
    } catch (error) {
      console.error('[OTEL] Error recording auth failure:', error);
    }
  }
  
  /**
   * Record key derivation with real OTEL metrics
   */
  static recordKeyDerivation(duration_ms, kdf_type = 'PBKDF2') {
    if (!this.isEnabled) return;
    
    try {
      this.counters.kdf_operations.add(1, {
        kdf_type: kdf_type,
        status: 'success'
      });
      
      this.histograms.kdf_duration.record(duration_ms, {
        kdf_type: kdf_type
      });
    } catch (error) {
      console.error('[OTEL] Error recording KDF metrics:', error);
    }
  }
  
  /**
   * Create distributed tracing span for crypto operations
   */
  static createCryptoSpan(operation, callback) {
    if (!this.isEnabled || !this.tracer) {
      return callback();
    }
    
    return this.tracer.startActiveSpan(`averox.${operation}`, (span) => {
      try {
        span.setAttributes({
          'averox.operation': operation,
          'averox.sdk.version': '2.0.0'
        });
        
        const result = callback();
        
        // Handle async operations
        if (result && typeof result.then === 'function') {
          return result
            .then(value => {
              span.setStatus({ code: otelAPI.SpanStatusCode.OK });
              span.end();
              return value;
            })
            .catch(error => {
              span.setStatus({ 
                code: otelAPI.SpanStatusCode.ERROR,
                message: error.message
              });
              span.end();
              throw error;
            });
        } else {
          span.setStatus({ code: otelAPI.SpanStatusCode.OK });
          span.end();
          return result;
        }
      } catch (error) {
        span.setStatus({
          code: otelAPI.SpanStatusCode.ERROR,
          message: error.message
        });
        span.end();
        throw error;
      }
    });
  }
  
  /**
   * Enhanced instrumentation wrapper for crypto operations
   */
  static instrumentCryptoOperation(operation, cryptoFn, algorithm = 'AES-256-GCM') {
    return async function(...args) {
      const startTime = Date.now();
      
      return RealOpenTelemetryIntegration.createCryptoSpan(operation, async () => {
        try {
          const result = await cryptoFn.apply(this, args);
          const duration = Date.now() - startTime;
          
          // Record appropriate metrics
          if (operation === 'encrypt') {
            RealOpenTelemetryIntegration.recordEncryptSuccess(duration, algorithm);
          } else if (operation === 'decrypt') {
            RealOpenTelemetryIntegration.recordDecryptSuccess(duration, algorithm);
          } else if (operation === 'kdf') {
            RealOpenTelemetryIntegration.recordKeyDerivation(duration, algorithm);
          }
          
          return result;
        } catch (error) {
          if (error.message.includes('Authentication failed') || 
              error.message.includes('invalid tag')) {
            RealOpenTelemetryIntegration.recordAuthFailure('auth_failure');
          } else {
            RealOpenTelemetryIntegration.recordAuthFailure(`${operation}_error`);
          }
          throw error;
        }
      });
    };
  }
  
  /**
   * Configure OTEL from environment variables
   */
  static configureFromEnvironment() {
    const enabled = process.env.OTEL_SDK_DISABLED !== 'true' && 
                   (process.env.AVEROX_TELEMETRY === 'enabled' || 
                    process.env.OTEL_TRACES_ENABLED === 'true' ||
                    process.env.OTEL_METRICS_ENABLED === 'true');
    
    if (enabled && otelAPI) {
      return this.initialize();
    } else {
      console.log('[OTEL] OpenTelemetry disabled or not available');
      return false;
    }
  }
}

// Auto-initialize from environment
if (process.env.NODE_ENV !== 'test') {
  RealOpenTelemetryIntegration.configureFromEnvironment();
}

module.exports = {
  RealOpenTelemetryIntegration,
  otelAPI
};