"""
salman 40 - Enterprise Python Performance Benchmarks
Generated: 2025-08-28T10:28:26.243Z
"""

import asyncio
import time
import statistics
import psutil
import concurrent.futures
from averox_crypto import AveroxCrypto, CryptoUtils
from async_crypto import AsyncAveroxCrypto, PerformanceMonitor

class PythonBenchmarkSuite:
    def __init__(self):
        self.results = {}
        self.monitor = PerformanceMonitor()
    
    async def run_all_benchmarks(self):
        """Run comprehensive benchmark suite"""
        print("🚀 Starting Python Enterprise Benchmarks...")
        
        await self.benchmark_sync_vs_async()
        await self.benchmark_encryption_algorithms()
        await self.benchmark_large_data()
        await self.benchmark_concurrent_operations()
        self.benchmark_memory_usage()
        
        self.generate_report()
    
    async def benchmark_sync_vs_async(self):
        """Compare sync vs async performance"""
        print("⚡ Benchmarking sync vs async...")
        
        master_key = CryptoUtils.generate_master_key()
        sync_crypto = AveroxCrypto(master_key)
        async_crypto = AsyncAveroxCrypto(master_key)
        
        test_data = "benchmark test data " * 100
        iterations = 1000
        
        # Sync benchmark
        sync_start = time.time()
        for _ in range(iterations):
            encrypted = sync_crypto.encrypt(test_data)
            sync_crypto.decrypt(encrypted)
        sync_time = time.time() - sync_start
        
        # Async benchmark
        async_start = time.time()
        tasks = []
        for _ in range(iterations):
            task = self._async_encrypt_decrypt(async_crypto, test_data)
            tasks.append(task)
        await asyncio.gather(*tasks)
        async_time = time.time() - async_start
        
        self.results['sync_vs_async'] = {
            'sync_ops_per_second': (iterations * 2 / sync_time),
            'async_ops_per_second': (iterations * 2 / async_time),
            'performance_gain': f"{((sync_time / async_time - 1) * 100):.1f}%"
        }
        
        sync_crypto.destroy()
        async_crypto.destroy()
    
    async def _async_encrypt_decrypt(self, crypto, data):
        """Helper for async encrypt/decrypt"""
        encrypted = await crypto.encrypt_async(data)
        return await crypto.decrypt_async(encrypted)
    
    async def benchmark_encryption_algorithms(self):
        """Benchmark different encryption algorithms"""
        print("🔐 Benchmarking encryption algorithms...")
        
        master_key = CryptoUtils.generate_master_key()
        crypto = AveroxCrypto(master_key)
        
        test_data = "x" * 10240  # 10KB
        iterations = 1000
        
        algorithms = ['aes-256-gcm', 'chacha20-poly1305']
        
        for algorithm in algorithms:
            start_time = time.time()
            for _ in range(iterations):
                encrypted = crypto.encrypt(test_data, algorithm=algorithm)
                crypto.decrypt(encrypted)
            elapsed = time.time() - start_time
            
            self.results[f'{algorithm}_performance'] = {
                'ops_per_second': (iterations * 2 / elapsed),
                'throughput_mbps': ((len(test_data) * iterations * 2) / elapsed / 1024 / 1024),
                'avg_latency_ms': (elapsed / iterations / 2 * 1000)
            }
        
        crypto.destroy()
    
    async def benchmark_large_data(self):
        """Benchmark large data encryption"""
        print("📊 Benchmarking large data operations...")
        
        master_key = CryptoUtils.generate_master_key()
        crypto = AsyncAveroxCrypto(master_key)
        
        sizes = [1024*1024, 10*1024*1024, 100*1024*1024]  # 1MB, 10MB, 100MB
        
        for size in sizes:
            data = "x" * size
            size_label = f"{size // 1024 // 1024}MB"
            
            start_time = time.time()
            encrypted = await crypto.encrypt_async(data)
            encryption_time = time.time() - start_time
            
            start_time = time.time()
            await crypto.decrypt_async(encrypted)
            decryption_time = time.time() - start_time
            
            self.results[f'large_data_{size_label}'] = {
                'encryption_time_s': encryption_time,
                'decryption_time_s': decryption_time,
                'total_time_s': encryption_time + decryption_time,
                'throughput_mbps': (size / (encryption_time + decryption_time) / 1024 / 1024)
            }
        
        crypto.destroy()
    
    async def benchmark_concurrent_operations(self):
        """Benchmark concurrent crypto operations"""
        print("🔄 Benchmarking concurrent operations...")
        
        master_key = CryptoUtils.generate_master_key()
        crypto = AsyncAveroxCrypto(master_key)
        
        concurrency_levels = [10, 50, 100, 200]
        test_data = "concurrent test data"
        
        for concurrency in concurrency_levels:
            start_time = time.time()
            
            tasks = []
            for _ in range(concurrency):
                task = self._async_encrypt_decrypt(crypto, test_data)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start_time
            
            successful = sum(1 for r in results if not isinstance(r, Exception))
            
            self.results[f'concurrent_{concurrency}'] = {
                'total_operations': concurrency,
                'successful': successful,
                'failed': concurrency - successful,
                'ops_per_second': (successful / elapsed),
                'success_rate': f"{(successful / concurrency * 100):.1f}%"
            }
        
        crypto.destroy()
    
    def benchmark_memory_usage(self):
        """Benchmark memory usage patterns"""
        print("💾 Benchmarking memory usage...")
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        instances = []
        for _ in range(1000):
            master_key = CryptoUtils.generate_master_key()
            instances.append(AveroxCrypto(master_key))
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Cleanup
        for instance in instances:
            instance.destroy()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        self.results['memory_usage'] = {
            'initial_memory_mb': initial_memory,
            'peak_memory_mb': peak_memory,
            'final_memory_mb': final_memory,
            'memory_per_instance_kb': ((peak_memory - initial_memory) * 1024 / 1000)
        }
    
    def generate_report(self):
        """Generate comprehensive benchmark report"""
        print("\n📋 Python Enterprise Benchmark Report")
        print("=" * 40)
        
        import json
        print(json.dumps(self.results, indent=2))
        
        with open('python-benchmark-results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\n💾 Results saved to python-benchmark-results.json")

# CLI runner
async def main():
    suite = PythonBenchmarkSuite()
    await suite.run_all_benchmarks()

if __name__ == "__main__":
    asyncio.run(main())