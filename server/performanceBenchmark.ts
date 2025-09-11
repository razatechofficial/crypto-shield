/**
 * Simple Performance Benchmark Module
 * Basic throughput and latency testing for different payload sizes
 */

import { performance } from 'perf_hooks';
import { randomBytes } from 'crypto';

// Simple benchmark result structure
export interface BenchmarkResult {
  algorithm: string;
  operation: string;
  payloadSize: number;
  iterations: number;
  totalTimeMs: number;
  avgLatencyMs: number;
  throughputOpsPerSec: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
}

// Simple benchmark configuration
export interface BenchmarkConfig {
  algorithms: string[];
  payloadSizes: number[];
  iterations: number;
}

/**
 * Simple Performance Benchmark Runner
 * Minimal implementation for basic throughput/latency testing
 */
export class SimpleBenchmarkRunner {
  private defaultConfig: BenchmarkConfig = {
    algorithms: ['AES-256-GCM', 'ChaCha20-Poly1305'],
    payloadSizes: [64, 256, 1024, 4096],
    iterations: 1000
  };

  /**
   * Run simple benchmark suite
   */
  async runBasicBenchmarks(config?: Partial<BenchmarkConfig>): Promise<BenchmarkResult[]> {
    const benchConfig = { ...this.defaultConfig, ...config };
    const results: BenchmarkResult[] = [];

    for (const algorithm of benchConfig.algorithms) {
      for (const payloadSize of benchConfig.payloadSizes) {
        // Benchmark encryption
        const encryptResult = await this.benchmarkOperation(
          algorithm,
          'encrypt',
          payloadSize,
          benchConfig.iterations
        );
        results.push(encryptResult);

        // Benchmark decryption
        const decryptResult = await this.benchmarkOperation(
          algorithm,
          'decrypt',
          payloadSize,
          benchConfig.iterations
        );
        results.push(decryptResult);
      }
    }

    return results;
  }

  /**
   * Benchmark a single operation
   */
  private async benchmarkOperation(
    algorithm: string,
    operation: string,
    payloadSize: number,
    iterations: number
  ): Promise<BenchmarkResult> {
    const latencies: number[] = [];
    
    // Generate test data
    const testData = randomBytes(payloadSize);
    
    const startTime = performance.now();
    
    // Run iterations with limited batch size to avoid blocking
    const batchSize = Math.min(iterations, 100);
    
    for (let i = 0; i < iterations; i += batchSize) {
      const currentBatch = Math.min(batchSize, iterations - i);
      
      for (let j = 0; j < currentBatch; j++) {
        const opStart = performance.now();
        
        // Simulate crypto operation (minimal overhead)
        await this.simulateCryptoOperation(algorithm, operation, testData);
        
        const opEnd = performance.now();
        latencies.push(opEnd - opStart);
      }
      
      // Yield control every batch to avoid blocking
      if (i + batchSize < iterations) {
        await new Promise(resolve => setImmediate(resolve));
      }
    }
    
    const endTime = performance.now();
    const totalTimeMs = endTime - startTime;
    
    // Calculate statistics
    latencies.sort((a, b) => a - b);
    const avgLatencyMs = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
    const p50LatencyMs = latencies[Math.floor(latencies.length * 0.5)];
    const p95LatencyMs = latencies[Math.floor(latencies.length * 0.95)];
    const throughputOpsPerSec = (iterations / totalTimeMs) * 1000;

    return {
      algorithm,
      operation,
      payloadSize,
      iterations,
      totalTimeMs,
      avgLatencyMs,
      throughputOpsPerSec,
      p50LatencyMs,
      p95LatencyMs
    };
  }

  /**
   * Simulate crypto operation with minimal overhead
   */
  private async simulateCryptoOperation(
    algorithm: string,
    operation: string,
    data: Buffer
  ): Promise<void> {
    // Simple simulation - just enough work to measure something meaningful
    // In a real implementation, this would call actual crypto operations
    const iterations = Math.min(data.length / 64, 10);
    for (let i = 0; i < iterations; i++) {
      // Minimal computation to simulate crypto work
      data.readUInt32BE(i % (data.length - 4));
    }
  }
}

// Export singleton instance
export const benchmarkRunner = new SimpleBenchmarkRunner();