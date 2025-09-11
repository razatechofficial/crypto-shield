/**
 * Simple Telemetry Hook
 * Minimal, disabled by default telemetry collection
 */

import { storage } from './storage';
import type { InsertPerformanceMetric } from '@shared/schema';

// Simple telemetry configuration - disabled by default
export interface TelemetryConfig {
  enabled: boolean;
  tenantId?: string;
}

// Default configuration - DISABLED by default
const DEFAULT_CONFIG: TelemetryConfig = {
  enabled: false, // CRITICAL: Disabled by default
};

/**
 * Simple Telemetry Hook
 * Only collects data if explicitly enabled
 */
export class SimpleTelemetry {
  private config: TelemetryConfig = DEFAULT_CONFIG;

  constructor(config?: Partial<TelemetryConfig>) {
    // Only enable if explicitly requested
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      enabled: config?.enabled === true // Explicit check required
    };
  }

  /**
   * Enable telemetry (must be called explicitly)
   */
  enable(tenantId: string): void {
    this.config.enabled = true;
    this.config.tenantId = tenantId;
  }

  /**
   * Disable telemetry (default state)
   */
  disable(): void {
    this.config.enabled = false;
    this.config.tenantId = undefined;
  }

  /**
   * Record performance metric (only if enabled)
   */
  async recordPerformanceMetric(data: {
    metricType: string;
    value: number;
    unit: string;
    sdkId?: string;
    metadata?: Record<string, any>;
  }): Promise<void> {
    // Early return if disabled (no work done)
    if (!this.config.enabled || !this.config.tenantId) {
      return;
    }

    try {
      await storage.createPerformanceMetric({
        tenantId: this.config.tenantId,
        metricType: data.metricType,
        value: data.value,
        unit: data.unit,
        sdkId: data.sdkId,
        metadata: data.metadata || {}
      });
    } catch (error) {
      // Silent fail - telemetry should never break the application
      console.debug('Telemetry recording failed:', error);
    }
  }

  /**
   * Check if telemetry is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }
}

// Export singleton instance - DISABLED by default
export const telemetry = new SimpleTelemetry();