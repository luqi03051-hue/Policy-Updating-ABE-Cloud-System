import time
import os
from ade_abe import encrypt, decrypt   # 换成你真实的 import

def bench_file_size():
    print("=== File size vs Encrypt time ===")
    sizes = [1024, 10*1024, 100*1024, 500*1024]  # 1KB, 10KB, 100KB, 500KB
    
    for size in sizes:
        data = os.urandom(size)
        start = time.perf_counter()
        ct = encrypt(data, policy="A and B")
        end = time.perf_counter()
        
        print(f"Size: {size/1024:.1f} KB  | Encrypt time: {(end-start)*1000:.2f} ms")


def bench_policy_complexity():
    print("\n=== Policy size vs Decrypt time ===")
    
    policies = [
        "A",
        "A and B",
        "A and B and C and D",
        "A and B and C and D and E and F"
    ]
    
    data = b"hello world"
    
    for policy in policies:
        ct = encrypt(data, policy=policy)
        
        start = time.perf_counter()
        pt = decrypt(ct, sk_valid)  # 你自己的有效 secret key
        end = time.perf_counter()
        
        print(f"Policy: {policy}  | Decrypt time: {(end-start)*1000:.2f} ms")


if __name__ == "__main__":
    bench_file_size()
    bench_policy_complexity()
