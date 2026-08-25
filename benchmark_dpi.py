import ctypes
import os
import platform
import timeit

lib_path = "./libdpi.so" if platform.system() != "Windows" else "./libdpi.dll"

if not os.path.exists(lib_path):
    print(f"[-] Error: {lib_path} not found. Please compile the C library first.")
    exit(1)

c_dpi = ctypes.CDLL(os.path.abspath(lib_path))

# Bindings
c_dpi.inspect_payload.argtypes = [ctypes.c_char_p, ctypes.c_int]
c_dpi.inspect_payload.restype = ctypes.c_int

c_dpi.inspect_batch.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int)
]
c_dpi.inspect_batch.restype = ctypes.c_int

TEST_PAYLOAD = (
    b"POST /api/v1/login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 45\r\n\r\n"
    b'{"username": "admin\' OR \'1\'=\'1", "pass": "123"}'
) * 5

SIGNATURES = ["' OR '1'='1", "UNION SELECT", "<script>", "../", "etc/passwd", "cmd.exe"]

def dpi_python_batch(payloads):
    results = []
    for p in payloads:
        p_str = p.decode('utf-8', errors='ignore')
        results.append(any(sig in p_str for sig in SIGNATURES))
    return results

def run_benchmark():
    ITERATIONS = 100_000
    print(f"=== NetGuard DPI Benchmark ({ITERATIONS:,} Packets) ===")

    payloads = [TEST_PAYLOAD] * ITERATIONS
    
    # 1. Python Pure Batch
    py_time = timeit.timeit(lambda: dpi_python_batch(payloads), number=1)
    py_pps = ITERATIONS / py_time

    # 2. C Native Batch Setup
    c_payloads = (ctypes.c_char_p * ITERATIONS)(*payloads)
    c_lengths = (ctypes.c_int * ITERATIONS)(*[len(p) for p in payloads])
    c_results = (ctypes.c_int * ITERATIONS)()

    c_time = timeit.timeit(lambda: c_dpi.inspect_batch(c_payloads, c_lengths, ITERATIONS, c_results), number=1)
    c_pps = ITERATIONS / c_time

    speedup = py_time / c_time

    print(f"🐍 Python Engine:  {py_time:.4f} sec | {py_pps:,.0f} Packets/sec")
    print(f"⚡ C Extension:    {c_time:.4f} sec | {c_pps:,.0f} Packets/sec")
    print(f"🚀 Speedup Factor: {speedup:.2f}x faster with C Extension!")

if __name__ == "__main__":
    run_benchmark()