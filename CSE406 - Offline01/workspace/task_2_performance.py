import random
import time
import pandas as pd
from task_2_ecc import *

def perform_key_exchange(ecc, G, a, b, p, k):
    k_a = random.randint(2**(k-1), p - 1)

    start_time = time.time()
    A = ecc.scalar_multiply(k_a, G, a, p)
    A_time = time.time() - start_time
    
    k_b = random.randint(2**(k-1), p - 1)

    start_time = time.time()
    B = ecc.scalar_multiply(k_b, G, a, p)
    B_time = time.time() - start_time

    start_time = time.time()
    R_a = ecc.scalar_multiply(k_a, B, a, p)
    R_time = time.time() - start_time

    R_b = ecc.scalar_multiply(k_b, A, a, p)
    
    assert R_a == R_b
    return [A_time*1000, B_time*1000, R_time*1000]

def measure_performance(ecc, k):
    [G, a, b, p] = ecc.generate_shared_parameters(k)
    return perform_key_exchange(ecc, G, a, b, p, k)

def main():
    metrics = []
    ecc = ECC()
    for k in [128, 192, 256]:
        # Run the function 5 times
        results = [measure_performance(ecc, k) for _ in range(5)]

        # Calculate the average of each index of the tuple
        averages = [
            sum(values) / len(values)
            for values in zip(*results)
        ]
        averages = ['%.2f' % elem for elem in averages]
        metrics.append([k]+averages)

    df = pd.DataFrame(metrics, columns=['k', 'A', 'B', 'R'])
    print(df.to_string(index=False))

if __name__ == "__main__":
    main()
