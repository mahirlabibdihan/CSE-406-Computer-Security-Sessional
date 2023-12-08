
import random
import math
from sympy import randprime

class ECC:
    def __init__(self):   
        pass
    
    # Fermat's little
    def mod_inv(self, a, p):
        assert math.gcd(a, p) == 1, "Mod inverse doesn't exist"
        return pow(a, p-2, p)

    # Slide
    def point_addition(self, P, Q, a, p):
            # Perform point addition on the elliptic curve
        if P == 0:
            return Q
        if Q == 0:
            return P

        x_1, y_1 = P
        x_2, y_2 = Q
        
        if P != Q:
            # Point addition
            s = ((y_2 - y_1) * self.mod_inv(x_2 - x_1, p)) % p
        else:
            # Point doubling
            s = ((3 * x_1**2 + a) * self.mod_inv(2 * y_1, p)) % p


        x_3 = (s**2 - x_1 - x_2) % p
        y_3 = (s * (x_1 - x_3) - y_1) % p

        return x_3, y_3

    # Slide
    def scalar_multiply(self, d, P, a, n):
        T = P
        for d_i in bin(d)[3:]:
            T = self.point_addition(T, T, a, n) # Point doubling
            if d_i == '1':
                T = self.point_addition(T, P, a, n) # Point addition
        return T

    def is_singular(self, a, b, p):
        return (4 * a**3 + 27 * b**2) % p == 0

    def generate_random_curve(self, p):
        a, b = 0, 0
        while True:
            a = random.randint(1, p - 1)
            b = random.randint(1, p - 1)
            if not self.is_singular(a, b, p):
                break
        return [a, b]

    # https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    def legendre_symbol(self, a, p):
        return pow(a, (p - 1) // 2, p)

    def tonelli_shanks(self, n, p):
        # First, it checks if n is a quadratic residue modulo p using the Legendre symbol. If not, it returns None since no square root exists.
        if self.legendre_symbol(n, p) != 1:
            return None

        # It then factors p - 1 into the form q * 2^s where q is odd.
        q, s = p - 1, 0
        while q & 1 == 0:
            q >>= 1
            s += 1

        # if s is 1, it calculates and returns the square root directly using a simplified formula.
        if s == 1:
            return pow(n, (p + 1) // 4, p)

        # Otherwise, it finds a quadratic non-residue z modulo p.
        for z in range(2, p):
            if self.legendre_symbol(z, p) == p - 1:
                break
        # It initializes variables c, r, and t
        c = pow(z, q, p)
        r = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        t2 = 0

        # enters a loop until (t - 1) % p is 0.
        while (t - 1) % p != 0:
            
            # Inside the loop, it calculates a value t2
            t2 = (t * t) % p
            
            # Iterates to find the smallest i such that (t2 - 1) % p is 0.
            for i in range(1, m):
                if (t2 - 1) % p == 0:
                    break
                t2 = (t2 * t2) % p

            b = pow(c, 1 << (m - i - 1), p)
            r = (r * b) % p
            c = (b * b) % p
            t = (t * c) % p
            m = i

        return r

    def generate_shared_parameters(self, k):
        p = randprime(2**(k-1), 2**k-1)
        [a, b] = self.generate_random_curve(p)
        
        while True:
            x = random.randint(1, p - 1)
            # y^2 = x^3 + ax + b (mod p)
            
            y_square = (x**3+a*x+b) % p 

            y = self.tonelli_shanks(y_square,p)
            if y is not None:
                break
            
        assert y**2 % p == y_square
        G = (x, y)
        return G, a, b, p

def main():
    ecc = ECC()
    k = 128
    [G, a, b, p] = ecc.generate_shared_parameters(k)
    print("p:",p)
    print("a:",a)
    print("b:",b)
    print("G:",G)

    k_a = random.randint(2**(k-1), p - 1)
    A = ecc.scalar_multiply(k_a, G, a, p)
    k_b = random.randint(2**(k-1), p - 1)
    B = ecc.scalar_multiply(k_b, G, a, p)
    R_a = ecc.scalar_multiply(k_a, B, a, p)
    R_b = ecc.scalar_multiply(k_b, A, a, p)
    assert R_a == R_b
    
    print("Shared key:", R_a[0])
    
if __name__ == "__main__":
    main()
