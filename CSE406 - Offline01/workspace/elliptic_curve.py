
import random
import time
import math
import pandas as pd
from sympy import randprime 

def mod_inverse(a, p):
    return pow(a, p-2, p)


def pointAddition(P, Q, a, p):
    # Perform point addition on the elliptic curve
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    if P != Q:
        m = ((Q[1] - P[1]) * mod_inverse(Q[0] - P[0], p)) % p
    else:
        m = ((3 * P[0]**2 + a) * mod_inverse(2 * P[1], p)) % p

    x = (m**2 - P[0] - Q[0]) % p
    y = (m * (P[0] - x) - P[1]) % p

    return x, y


def scalarMultiply(d, P, a, n):
    # Perform scalar multiplication on the elliptic curve
    T = P
    for d_i in bin(d)[3:]:
        T = pointAddition(T, T, a, n)
        if d_i == '1':
            T = pointAddition(T, P, a, n)
    return T

# Function to generate a random coefficient
def random_coefficient(p):
    return random.randint(1, p - 1)

# Function to check if the curve is singular
def is_singular(a, b, p):
    discriminant = (4 * a**3 + 27 * b**2) % p
    return discriminant == 0

def generate_random_curve(p):
    # Choose coefficients a and b randomly
    a, b = 0, 0  # Initialize a and b to 0 to enter the loop
    # Ensure that the curve is nonsingular
    while a == 0 and b == 0:
        a = random_coefficient(p)
        b = random_coefficient(p)
        # Check for singularity
        if is_singular(a, b, p):
            a, b = 0, 0  # Reset coefficients if singular    
    return [a,b]

def generate_shared_parameters(k):
    # Define elliptic curve parameters
    p = randprime(2**(k-1),(2**k)-1)

    [a,b] = generate_random_curve(p)

    X_g = 0
    Y_g = int(math.sqrt((X_g**3+a*X_g+b) % p))
    G = (X_g, Y_g)

    return G, a, b, p

def perform_key_exchange(G, a, b, p):
    # Alice chooses a secret key Ka
    k_a = random.randint(1, p - 1)

    start_time = time.time()
    A = scalarMultiply(k_a, G, a, p)
    A_time = time.time() - start_time

    k_b = random.randint(1, p - 1)

    start_time = time.time()
    B = scalarMultiply(k_b, G, a, p)
    B_time = time.time() - start_time

    start_time = time.time()
    R_a = scalarMultiply(k_a, B, a, p)
    R_time = time.time() - start_time

    R_b = scalarMultiply(k_b, A, a, p)
    assert R_a == R_b
    
    return [A_time*1000, B_time*1000, R_time*1000]

def measure_performance(k):
    [G,a,b,p] = generate_shared_parameters(k)
    return perform_key_exchange(G,a,b,p)


def main():
    metrics = []
    for k in [128, 192, 256]:
        # Run the function 5 times
        results = [measure_performance(k) for _ in range(5)]

        # Calculate the average of each index of the tuple
        averages = [
            sum(values) / len(values)
            for values in zip(*results)
        ]
        averages = ['%.2f' % elem for elem in averages]
        metrics.append([k]+averages)

    columns = pd.MultiIndex.from_tuples([
        
        ('Computation Time for', 'A'),
        ('Computation Time for', 'B'),
        ('Computation Time for', 'R'),
        # Add more columns if needed
    ])

    df = pd.DataFrame(metrics, columns=['k', 'A', 'B', 'R'])
    # df.set_index('k', inplace=True)
    # df.index.name = 'k'
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
