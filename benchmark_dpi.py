import ctypes
import os
import sys
import time

# ---------------------------------------------------------------------------
# 1. Load Native C Extension
# ---------------------------------------------------------------------------
lib_path = "./libdpi.dll" if sys.platform == "win32" else "./libdpi.so"

if not os.path.exists(lib_path):
    print(f"[-] Shared library not found at {lib_path}. Compile it first.")
    sys.exit(1)

c_lib = ctypes.CDLL(lib_path)

# Define C Function Signature for inspect_batch:
# int inspect_batch(const char** payloads, const int* lengths, int count, int* results)
c_lib.inspect_batch.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
]
c_lib.inspect_batch.restype = ctypes.c_int


# ---------------------------------------------------------------------------
# 2. Pure Python Engine Implementation
# ---------------------------------------------------------------------------
SIGNATURES_PY = [
    b"' OR '1'='1",
    b"UNION SELECT",
    b"<script>",
    b"../",
    b"etc/passwd",
    b"cmd.exe",
]


def inspect_payload_py(payload: bytes) -> int:
    for sig in SIGNATURES_PY:
        if sig in payload:
            return 1
    return 0


def run_python_benchmark(payloads: list[bytes]) -> float:
    start_time = time.perf_counter()
    results = [inspect_payload_py(p) for p in payloads]
    end_time = time.perf_counter()
    return end_time - start_time


# ---------------------------------------------------------------------------
# 3. Native C Extension Batch Benchmark
# ---------------------------------------------------------------------------
def prepare_c_buffers(payloads: list[bytes]):
    count = len(payloads)
    
    # Safe allocation without python list unpacking unpacking (*payloads)
    payload_ptrs = (ctypes.c_char_p * count)()
    lengths = (ctypes.c_int * count)()
    results = (ctypes.c_int * count)()

    for i, p in enumerate(payloads):
        payload_ptrs[i] = p
        lengths[i] = len(p)

    return payload_ptrs, lengths, count, results


def run_c_batch_benchmark(payload_ptrs, lengths, count, results) -> float:
    # Benchmark EXCLUSIVELY the C engine execution time
    start_time = time.perf_counter()
    c_lib.inspect_batch(payload_ptrs, lengths, count, results)
    end_time = time.perf_counter()

    return end_time - start_time


# ---------------------------------------------------------------------------
# 4. Benchmark Execution & Comparison
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    NUM_PACKETS = 100_000

    # Synthetic Dataset Generation (Mix of clean & malicious payloads)
    sample_clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    sample_malicious = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR '1'='1"

    print(f"=== NetGuard DPI Benchmark ({NUM_PACKETS:,} Packets) ===")

    test_payloads = [
        sample_malicious if i % 10 == 0 else sample_clean
        for i in range(NUM_PACKETS)
    ]

    # Run Python Benchmark
    py_time = run_python_benchmark(test_payloads)
    py_pps = NUM_PACKETS / py_time
    print(f"🐍 Python Engine:  {py_time:.4f} sec | {py_pps:,.0f} Packets/sec")

    # Prepare C Buffers (Out of measurement scope to eliminate Python setup overhead)
    c_buffers = prepare_c_buffers(test_payloads)

    # Run C Batch Benchmark
    c_time = run_c_batch_benchmark(*c_buffers)
    c_pps = NUM_PACKETS / c_time
    print(f"⚡ C Extension:     {c_time:.4f} sec | {c_pps:,.0f} Packets/sec")

    # Results
    speedup = py_time / c_time if c_time > 0 else 0
    print(f"🚀 Speedup Factor: {speedup:.2f}x faster with C Extension!")