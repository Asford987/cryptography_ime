import argparse
import json
import tracemalloc
import time


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('args', help='input values for the cryptography module')
    parser.add_argument('--algorithm', choices=['saber', 'rsa'], help='the algorithm to use', required=True)
    parser.add_argument('--public-key', '-p', help='output file name for the public key', type=str, required=True)
    parser.add_argument('--private-key', '-q', help='output file name for the private key', type=str, required=True)
    parser.add_argument('--strength', '-s', help='the strength of the algorithm', type=int, default=2)
    parser.add_argument('--trace-memory', '-m', help='trace memory usage', action='store_true')
    parser.add_argument('--trace-time', '-t', help='trace time usage', action='store_true')
    return parser.parse_args()

def trace_memory(function, *args, **kwargs):
    tracemalloc.start()
    start_snapshot = tracemalloc.take_snapshot()

    result = function(*args, **kwargs)

    end_snapshot = tracemalloc.take_snapshot()
    stats = end_snapshot.compare_to(start_snapshot, 'lineno')
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    top_stats = []
    for stat in stats[:10]:
        top_stats.append({
            "filename": stat.traceback[0].filename,
            "lineno": stat.traceback[0].lineno,
            "size_kb": stat.size / 1024,
            "count": stat.count,
            "line": stat.traceback[0].line
        })

    return {
        "function": function.__name__,
        "args": args,
        "kwargs": kwargs,
        "result": result,
        "memory_usage_kb": {
            "current": current / 1024,
            "peak": peak / 1024
        },
        "top_memory_stats": top_stats
    }

def trace_time(function, *args, **kwargs):
    start_time = time.time()
    result = function(*args, **kwargs)
    end_time = time.time()

    elapsed = end_time - start_time

    return {
        "function": function.__name__,
        "args": args,
        "kwargs": kwargs,
        "result": result,
        "execution_time": {
            "seconds": elapsed,
            "milliseconds": elapsed * 1000,
            "microseconds": elapsed * 1_000_000
        }
    }
    
def main():
    args = parse_args()
    if args.algorithm == 'saber':
        from saber import Saber
        saber = Saber()
        if args.trace_memory: 
            metrics = trace_memory(saber.generate_keypair, args.strength)
            with open('metrics_memory.json', 'w') as f:
                json.dump(metrics, f)
        elif args.trace_time:
            metrics = trace_time(saber.generate_keypair, args.strength)
            with open('metrics_time.json', 'w') as f:
                json.dump(metrics, f)
        else:
            saber.generate_keypair(args.strength)
        with open(args.public_key, 'wb') as f:
            f.write(saber.public_key)
        with open(args.private_key, 'wb') as f:
            f.write(saber.private_key)
        
    if args.algorithm == 'rsa':
        from pyrsa import RSA
        rsa = RSA()
        if args.trace_memory: 
            metrics = trace_memory(rsa.generate_keypair, args.strength)
            with open('metrics_memory.json', 'w') as f:
                json.dump(metrics, f)
        elif args.trace_time:
            metrics = trace_time(rsa.generate_keypair, args.strength)
            with open('metrics_time.json', 'w') as f:
                json.dump(metrics, f)
        else:
            rsa.generate_keypair(args.strength)
        with open(args.public_key, 'wb') as f:
            f.write(rsa.public_key)
        with open(args.private_key, 'wb') as f:
            f.write(rsa.private_key)

if __name__ == '__main__':
    main()