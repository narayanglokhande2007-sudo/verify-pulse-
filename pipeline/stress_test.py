import time
import concurrent.futures
import json
import os
import sys

# Add project root to path to import local modules if needed
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)

# Mocking the handler for stress testing in a local environment
# In a real scenario, this would be an HTTP request to the Vercel/Node.js endpoint
def mock_verify_handler(url):
    """
    Simulates the logic in api/verify.js and api/ghost_agent.js
    to test the overall system performance under load.
    """
    start_time = time.time()
    
    # Simulate DB lookup (5-10ms)
    time.sleep(random.uniform(0.005, 0.01))
    
    # Simulate Ghost Agent analysis (50-100ms due to Puppeteer/Vision simulation)
    time.sleep(random.uniform(0.05, 0.1))
    
    # Simulate Meta Judge decision logic (1-2ms)
    time.sleep(random.uniform(0.001, 0.002))
    
    end_time = time.time()
    return end_time - start_time

import random

def run_stress_test(num_requests=100, concurrent_users=10):
    print(f"--- Starting Stress Test ---")
    print(f"Total Requests: {num_requests}")
    print(f"Concurrent Users: {concurrent_users}")

    latencies = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [executor.submit(mock_verify_handler, f"http://test-url-{i}.com") for i in range(num_requests)]
        for future in concurrent.futures.as_completed(futures):
            latencies.append(future.result())

    end_time = time.time()
    total_time = end_time - start_time

    print("\n--- Results ---")
    print(f"Total Time Taken: {total_time:.4f} seconds")
    print(f"Requests Per Second (RPS): {num_requests / total_time:.2f}")
    print(f"Average Latency: {sum(latencies) / len(latencies) * 1000:.2f} ms")
    print(f"Min Latency: {min(latencies) * 1000:.2f} ms")
    print(f"Max Latency: {max(latencies) * 1000:.2f} ms")
    
    # Percentiles
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95)] * 1000
    p99 = latencies[int(len(latencies) * 0.99)] * 1000
    print(f"P95 Latency: {p95:.2f} ms")
    print(f"P99 Latency: {p99:.2f} ms")

if __name__ == '__main__':
    run_stress_test(num_requests=200, concurrent_users=20)
