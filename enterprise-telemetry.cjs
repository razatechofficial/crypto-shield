/**
 * Enterprise OpenTelemetry Integration
 * Zero-config, opt-in telemetry with no secret data leakage
 * 
 * COMPLIANCE:
 * ✅ OpenTelemetry compatible metrics
 * ✅ Disabled by default
 * ✅ No secrets or PII in labels
 * ✅ Pluggable architecture
 * ✅ Environment-controlled activation
 */

/**
 * Production Telemetry System
 * Minimal OpenTelemetry hooks for enterprise monitoring
 */
class ProductionTelemetry {
  static metrics = {
    // Counters
    encrypt_ok: 0,
    decrypt_ok: 0,
    auth_fail: 0,
    key_derivation_ops: 0,
    total_operations: 0,
    
    // Histograms (stored as arrays for percentile calculation)
    aead_latency_ms: [],
    kdf_latency_ms: [],
    
    // Error tracking
    errors_by_type: {},
    
    // System info
    start_time: Date.now(),
    last_operation: null
  };
  
  static isEnabled = false;
  static telemetryEndpoint = null;
  static maxHistogramSize = 1000;
  
  static {
    // Auto-configure from environment variables
    this.configure();
  }
  
  /**
   * Configure telemetry from environment
   */
  static configure() {
    // Check multiple environment flags
    const enableFlags = [
      process.env.AVEROX_TELEMETRY === 'enabled',
      process.env.OTEL_ENABLED === 'true', 
      process.env.TELEMETRY_ENABLED === '1'
    ];
    
    this.isEnabled = enableFlags.some(flag => flag);
    this.telemetryEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || null;
    
    if (this.isEnabled) {
      console.log('[AVEROX_TELEMETRY] Telemetry enabled');
      if (this.telemetryEndpoint) {
        console.log(`[AVEROX_TELEMETRY] Endpoint: ${this.telemetryEndpoint}`);
      }
    }
  }
  
  /**
   * Record successful encryption operation
   * @param {number} latencyMs - Operation latency
   * @param {string} algorithm - Algorithm used (no key material)
   */
  static recordEncryptSuccess(latencyMs, algorithm = 'unknown') {
    if (!this.isEnabled) return;
    
    this.metrics.encrypt_ok++;
    this.metrics.total_operations++;
    this.addLatencySample('aead_latency_ms', latencyMs);
    this.metrics.last_operation = Date.now();
    
    this.emit('encrypt_success', {
      latency_ms: latencyMs,
      algorithm: algorithm,
      timestamp: Date.now()
    });
  }
  
  /**
   * Record successful decryption operation
   * @param {number} latencyMs - Operation latency
   * @param {string} algorithm - Algorithm used (no key material)
   */
  static recordDecryptSuccess(latencyMs, algorithm = 'unknown') {
    if (!this.isEnabled) return;
    
    this.metrics.decrypt_ok++;
    this.metrics.total_operations++;
    this.addLatencySample('aead_latency_ms', latencyMs);
    this.metrics.last_operation = Date.now();
    
    this.emit('decrypt_success', {
      latency_ms: latencyMs,
      algorithm: algorithm,
      timestamp: Date.now()
    });
  }
  
  /**
   * Record authentication failure (wrong tag, AAD mismatch)
   * @param {string} errorType - Error classification (no sensitive data)
   */
  static recordAuthFailure(errorType = 'auth_error') {
    if (!this.isEnabled) return;
    
    this.metrics.auth_fail++;
    this.metrics.total_operations++;
    this.incrementErrorCount(errorType);
    this.metrics.last_operation = Date.now();
    
    this.emit('auth_failure', {
      error_type: errorType,
      timestamp: Date.now()
    });
  }
  
  /**
   * Record key derivation operation
   * @param {number} latencyMs - KDF latency
   * @param {string} kdfType - KDF algorithm type
   */
  static recordKeyDerivation(latencyMs, kdfType = 'unknown') {
    if (!this.isEnabled) return;
    
    this.metrics.key_derivation_ops++;
    this.metrics.total_operations++;
    this.addLatencySample('kdf_latency_ms', latencyMs);
    this.metrics.last_operation = Date.now();
    
    this.emit('key_derivation', {
      latency_ms: latencyMs,
      kdf_type: kdfType,
      timestamp: Date.now()
    });
  }
  
  /**
   * Add latency sample to histogram
   * @private
   */
  static addLatencySample(histogramName, value) {
    const histogram = this.metrics[histogramName];
    histogram.push(value);
    
    // Keep histogram size bounded
    if (histogram.length > this.maxHistogramSize) {
      histogram.shift(); // Remove oldest sample
    }
  }
  
  /**
   * Increment error counter
   * @private
   */
  static incrementErrorCount(errorType) {
    this.metrics.errors_by_type[errorType] = (this.metrics.errors_by_type[errorType] || 0) + 1;
  }
  
  /**
   * Emit telemetry event (pluggable)
   * @private
   */
  static emit(eventType, data) {
    // OpenTelemetry-compatible event format
    const event = {
      name: `averox.crypto.${eventType}`,
      attributes: {
        ...data,
        service_name: 'averox-crypto-sdk',
        service_version: '2.0.0'
      },
      timestamp: Date.now() * 1000000 // nanoseconds for OTEL
    };
    
    if (this.telemetryEndpoint) {
      // In production, this would send to OTEL collector
      this.sendToCollector(event);
    } else {
      // Console output for development
      console.log(`[OTEL_EVENT] ${JSON.stringify(event)}`);
    }
  }
  
  /**
   * Send event to OpenTelemetry collector
   * @private
   */
  static sendToCollector(event) {
    // Placeholder for actual OTEL collector integration
    // In production, use @opentelemetry/exporter-otlp-http
    console.log(`[OTEL_EXPORT] ${this.telemetryEndpoint}: ${JSON.stringify(event)}`);
  }
  
  /**
   * Get current metrics snapshot
   * @returns {Object} Metrics summary (no sensitive data)
   */
  static getMetrics() {
    return {
      counters: {
        encrypt_ok: this.metrics.encrypt_ok,
        decrypt_ok: this.metrics.decrypt_ok,
        auth_fail: this.metrics.auth_fail,
        key_derivation_ops: this.metrics.key_derivation_ops,
        total_operations: this.metrics.total_operations
      },
      histograms: {
        aead_latency_p50: this.calculatePercentile(this.metrics.aead_latency_ms, 0.5),
        aead_latency_p95: this.calculatePercentile(this.metrics.aead_latency_ms, 0.95),
        aead_latency_p99: this.calculatePercentile(this.metrics.aead_latency_ms, 0.99),
        kdf_latency_p50: this.calculatePercentile(this.metrics.kdf_latency_ms, 0.5),
        kdf_latency_p95: this.calculatePercentile(this.metrics.kdf_latency_ms, 0.95)
      },
      errors: this.metrics.errors_by_type,
      system: {
        uptime_ms: Date.now() - this.metrics.start_time,
        last_operation_ago_ms: this.metrics.last_operation ? Date.now() - this.metrics.last_operation : null,
        telemetry_enabled: this.isEnabled
      }
    };
  }
  
  /**
   * Calculate percentile from histogram
   * @private
   */
  static calculatePercentile(samples, percentile) {
    if (samples.length === 0) return null;
    
    const sorted = [...samples].sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * percentile) - 1;
    return sorted[Math.max(0, index)];
  }
  
  /**
   * Reset all metrics (for testing)
   */
  static reset() {
    this.metrics = {
      encrypt_ok: 0,
      decrypt_ok: 0,
      auth_fail: 0,
      key_derivation_ops: 0,
      total_operations: 0,
      aead_latency_ms: [],
      kdf_latency_ms: [],
      errors_by_type: {},
      start_time: Date.now(),
      last_operation: null
    };
  }
  
  /**
   * Enable/disable telemetry programmatically
   * @param {boolean} enabled - Enable state
   */
  static setEnabled(enabled) {
    this.isEnabled = enabled;
    if (enabled) {
      console.log('[AVEROX_TELEMETRY] Telemetry enabled programmatically');
    } else {
      console.log('[AVEROX_TELEMETRY] Telemetry disabled programmatically');
    }
  }
}

/**
 * Instrumentation wrapper for crypto operations
 * Automatically records timing and success/failure
 */
class CryptoInstrumentation {
  /**
   * Wrap encryption function with telemetry
   * @param {Function} encryptFn - Encryption function
   * @param {string} algorithm - Algorithm name
   * @returns {Function} Instrumented function
   */
  static wrapEncrypt(encryptFn, algorithm = 'AES-256-GCM') {
    return async function(...args) {
      const startTime = Date.now();
      
      try {
        const result = await encryptFn.apply(this, args);
        const latency = Date.now() - startTime;
        ProductionTelemetry.recordEncryptSuccess(latency, algorithm);
        return result;
      } catch (error) {
        ProductionTelemetry.recordAuthFailure('encrypt_error');
        throw error;
      }
    };
  }
  
  /**
   * Wrap decryption function with telemetry
   * @param {Function} decryptFn - Decryption function
   * @param {string} algorithm - Algorithm name
   * @returns {Function} Instrumented function
   */
  static wrapDecrypt(decryptFn, algorithm = 'AES-256-GCM') {
    return async function(...args) {
      const startTime = Date.now();
      
      try {
        const result = await decryptFn.apply(this, args);
        const latency = Date.now() - startTime;
        ProductionTelemetry.recordDecryptSuccess(latency, algorithm);
        return result;
      } catch (error) {
        if (error.message.includes('Authentication failed') || 
            error.message.includes('invalid tag') ||
            error.message.includes('AAD mismatch')) {
          ProductionTelemetry.recordAuthFailure('auth_failure');
        } else {
          ProductionTelemetry.recordAuthFailure('decrypt_error');
        }
        throw error;
      }
    };
  }
  
  /**
   * Wrap KDF function with telemetry
   * @param {Function} kdfFn - KDF function
   * @param {string} kdfType - KDF algorithm type
   * @returns {Function} Instrumented function
   */
  static wrapKDF(kdfFn, kdfType = 'unknown') {
    return async function(...args) {
      const startTime = Date.now();
      
      try {
        const result = await kdfFn.apply(this, args);
        const latency = Date.now() - startTime;
        ProductionTelemetry.recordKeyDerivation(latency, kdfType);
        return result;
      } catch (error) {
        ProductionTelemetry.recordAuthFailure('kdf_error');
        throw error;
      }
    };
  }
}

module.exports = {
  ProductionTelemetry,
  CryptoInstrumentation
};