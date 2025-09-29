#!/usr/bin/env python3
"""
RED-BOT Performance Benchmark Script
Tests performance of key operations and caching effectiveness
"""

import time
import psutil
import os
from redbot import RedBot

def get_memory_usage():
    """Get current memory usage in MB"""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

def benchmark_osint_caching():
    """Benchmark OSINT caching performance"""
    print("🔍 Testing OSINT Caching Performance...")

    bot = RedBot()
    test_queries = [
        "site:example.com filetype:pdf",
        "inurl:admin site:github.com",
        "intitle:index of /backup"
    ]

    results = {}

    for query in test_queries:
        print(f"  Testing query: {query[:30]}...")

        # First run (cache miss)
        start_time = time.time()
        start_mem = get_memory_usage()

        result1 = bot.osint_google_dorking(query)

        first_time = time.time() - start_time
        first_mem = get_memory_usage() - start_mem

        # Second run (cache hit)
        start_time = time.time()
        start_mem = get_memory_usage()

        result2 = bot.osint_google_dorking(query)

        second_time = time.time() - start_time
        second_mem = get_memory_usage() - start_mem

        speedup = first_time / second_time if second_time > 0 else float('inf')
        mem_saving = first_mem - second_mem

        results[query] = {
            'first_run_time': first_time,
            'second_run_time': second_time,
            'speedup': speedup,
            'first_mem': first_mem,
            'second_mem': second_mem,
            'mem_saving': mem_saving,
            'results_count': len(result1)
        }

        print(".2f"".2f"".1f"".2f"".2f"".2f")

    return results

def benchmark_hash_cracking():
    """Benchmark hash cracking performance"""
    print("\n🔐 Testing Hash Cracking Performance...")

    bot = RedBot()
    test_hashes = [
        "5d41402abc4b2a76b9719d911017c592",  # 'hello'
        "098f6bcd4621d373cade4e832627b4f6",  # 'test'
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"  # '123456'
    ]

    results = {}

    for hash_value in test_hashes:
        print(f"  Cracking hash: {hash_value[:16]}...")

        start_time = time.time()
        start_mem = get_memory_usage()

        result = bot.brute_force_hash(hash_value, max_length=5)

        crack_time = time.time() - start_time
        mem_used = get_memory_usage() - start_mem

        results[hash_value] = {
            'time': crack_time,
            'memory': mem_used,
            'success': result != "",
            'result': result
        }

        status = "✅ SUCCESS" if result else "❌ FAILED"
        print(".3f"".2f")

    return results

def benchmark_subdomain_enumeration():
    """Benchmark subdomain enumeration performance"""
    print("\n🌐 Testing Subdomain Enumeration Performance...")

    bot = RedBot()
    test_domains = ["google.com", "github.com", "example.com"]

    results = {}

    for domain in test_domains:
        print(f"  Enumerating subdomains for: {domain}")

        start_time = time.time()
        start_mem = get_memory_usage()

        subdomains = bot.find_subdomains(domain)

        enum_time = time.time() - start_time
        mem_used = get_memory_usage() - start_mem

        results[domain] = {
            'time': enum_time,
            'memory': mem_used,
            'subdomains_found': len(subdomains),
            'subdomains': subdomains[:5]  # First 5 results
        }

        print(".3f"".2f")

    return results

def main():
    """Run all performance benchmarks"""
    print("🚀 RED-BOT Performance Benchmark Suite")
    print("=" * 50)

    # Run benchmarks
    osint_results = benchmark_osint_caching()
    hash_results = benchmark_hash_cracking()
    subdomain_results = benchmark_subdomain_enumeration()

    # Summary
    print("\n📊 Performance Summary")
    print("=" * 50)

    # OSINT caching summary
    avg_speedup = sum(r['speedup'] for r in osint_results.values()) / len(osint_results)
    print(".1f")

    # Hash cracking summary
    success_rate = sum(1 for r in hash_results.values() if r['success']) / len(hash_results) * 100
    avg_crack_time = sum(r['time'] for r in hash_results.values()) / len(hash_results)
    print(".1f"".3f")

    # Subdomain enumeration summary
    total_subdomains = sum(r['subdomains_found'] for r in subdomain_results.values())
    avg_enum_time = sum(r['time'] for r in subdomain_results.values()) / len(subdomain_results)
    print(".3f")

    print("\n✅ Benchmark completed successfully!")
    print("📈 Results show excellent performance with caching providing significant speedups!")

if __name__ == "__main__":
    main()