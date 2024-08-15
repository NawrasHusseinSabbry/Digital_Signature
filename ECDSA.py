# The 288 byte message that we signed and verified in our test in our research is:  
# The wisdom of today: Surround yourself with people whose eyes light 
# up when they see you coming, slowly is the fastest way to get to 
# where you want to be, and the top of one mountain is the bottom of the next _ so keep climbing.
import random
import hashlib
import time
import tracemalloc

tracemalloc.start()

def cswap(swap, x_0, x_1, prime):
    dummy = swap * ((x_0 - x_1) % prime)
    x_0 = (x_0 - dummy) % prime
    x_1 = (x_1 + dummy) % prime
    return x_0, x_1

def montgomery_ladder_proj(G, k, n, prime):
    if k == n:
        print("The point lies at infinity (Identity Element)")
        exit()

    elif k == 1:
        print(f"G = {G}")
        exit()

    else:
        # Since in the Weierstrass elliptic curve in the projective coordinate, we can't add the any point to the Identity element (0:1:0)
        # because the reuslt will be always equal to zero, then we will make the intiale values as (R0 = 2G and R1 = G) instead of 
        # (R0 = 2G and R1 = G) as it is suppose to be. To understand what is this suppose to mean, note the adding and doubling
        # equations for the Weierstrass elliptic curve (SCEP256K1) in the projective coordinate which they are are mentioned in the 
        # (https://hackmd.io/@cailynyongyong/HkuoMtz6o), last visit in 2024/08/12 in 10:00.

        # The following steps represent the Initialization for R0 and R1:
        x1, y1, z1 = G
        X1, Y1, Z1 = (x1, y1, z1) # This makes R1 = G

        x0, y0, z0 = G
        X0, Y0, Z0 = (x0, y0, z0)
        t = (3 * X0 * X0 + a * Z0 * Z0) % prime
        u = (Y0 * Z0) % prime
        v = (u * X0 * Y0) % prime
        w = (t * t - 8 * v) % prime
        X0 = (2 * u * w) % prime
        Y0 = (t * (4 * v - w) - 8 * Y0 * Y0 * u * u) % prime
        Z0 = (8 * u * u * u) % prime
        #This makes R0 = 2G
        # End of the Initialization steps 

        swap = 1
        k_bits = bin(k)[2:]  # Convert scalar to binary without unnecessary padding

        for i in range(1, len(k_bits)):
            bit = int(k_bits[i])
            swap ^= bit  # XOR with the current bit to determine swap value

            # Perform swaps based on the current bit
            X0, X1 = cswap(swap, X0, X1, prime)
            Y0, Y1 = cswap(swap, Y0, Y1, prime)
            Z0, Z1 = cswap(swap, Z0, Z1, prime)

            swap = bit  # Update swap to the current bit

            # Point addition (R1 + R0)
            u = (Y1 * Z0 - Y0 * Z1) % prime
            v = (X1 * Z0 - X0 * Z1) % prime
            w = (u * u * Z0 * Z1 - v * v * v - 2 * v * v * X0 * Z1) % prime
            X1 = (v * w) % prime
            Y1 = (u * (v * v * X0 * Z1 - w) - v * v * v * Y0 * Z1) % prime
            Z1 = (v * v * v * Z0 * Z1) % prime

            # Point doubling (R0 + R0)
            t = (3 * X0 * X0 + a * Z0 * Z0) % prime
            u = (Y0 * Z0) % prime
            v = (u * X0 * Y0) % prime
            w = (t * t - 8 * v) % prime
            X0 = (2 * u * w) % prime
            Y0 = (t * (4 * v - w) - 8 * Y0 * Y0 * u * u) % prime
            Z0 = (8 * u * u * u) % prime

        # Final swap to get the correct result
        X0, X1 = cswap(swap, X0, X1, prime)
        Y0, Y1 = cswap(swap, Y0, Y1, prime)
        Z0, Z1 = cswap(swap, Z0, Z1, prime)

        # Convert the final projective coordinates back to affine coordinates
        result = to_affine((X0, Y0, Z0), prime)
        return result

# The ECDSA based on the Weierstrass curve y^2 = x^3 + a*x + b in projective coordinates
def add_points_proj(P, Q, prime):
    x1, y1, z1 = P
    x2, y2, z2 = Q

    if P == Q:
        # Point Doubling
        # t is the slope calculation: t = 3*x1^2 + a*z1^2 (mod prime)
        t = (3 * x1 * x1 + a * z1 * z1) % prime
        # u = y1 * z1 (mod prime)
        u = (y1 * z1) % prime
        # v is an intermediate value for point calculation: v = u * x1 * y1 (mod prime)
        v = (u * x1 * y1) % prime
        # w is part of the x-coordinate for the resulting point: w = t^2 - 8*v (mod prime)
        w = (t * t - 8 * v) % prime
        # x3 = 2 * u * w (mod prime)
        x3 = (2 * u * w) % prime
        # y3 = t * (4*v - w) - 8 * y1^2 * u^2 (mod prime)
        y3 = (t * (4 * v - w) - 8 * y1 * y1 * u * u) % prime
        # z3 = 8 * u^3 (mod prime)
        z3 = (8 * u * u * u) % prime
    else:
        # Point Addition
        # u is the difference in y-coordinates scaled by z-coordinates: u = (y2*z1 - y1*z2) (mod prime)
        u = (y2 * z1 - y1 * z2) % prime
        # v is the difference in x-coordinates scaled by z-coordinates: v = (x2*z1 - x1*z2) (mod prime)
        v = (x2 * z1 - x1 * z2) % prime
        # w is a complex term involving u and v for the new x-coordinate: w = u^2 * z1 * z2 - v^3 - 2 * v^2 * x1 * z2 (mod prime)
        w = (u * u * z1 * z2 - v * v * v - 2 * v * v * x1 * z2) % prime
        # x3 = v * w (mod prime)
        x3 = (v * w) % prime
        # y3 = u * (v^2 * x1 * z2 - w) - v^3 * y1 * z2 (mod prime)
        y3 = (u * (v * v * x1 * z2 - w) - v * v * v * y1 * z2) % prime
        # z3 = v^3 * z1 * z2 (mod prime)
        z3 = (v * v * v * z1 * z2) % prime
    return x3, y3, z3

def to_affine(P, prime):
    # Converts projective coordinates (x, y, z) back to affine coordinates (x, y)
    x, y, z = P
    z_inv = pow(z, prime - 2, prime)  # Efficient inverse using Fermat's Little Theorem
    x_affine = (x * z_inv) % prime
    y_affine = (y * z_inv) % prime
    return x_affine, y_affine

def Binary_method_proj(G, k, n, prime):        
    if k == n:
        print("The point lies at infinity (Identity Element)")
        exit()

    # Perform scalar multiplication using the binary method in projective coordinates
    target_Point = G
    k_binary = bin(k)[2:]

    for i in range(1, len(k_binary)):
        current_bit = k_binary[i:i+1]

        # Doubling step: always performed
        target_Point = add_points_proj(target_Point, target_Point, prime)
        if current_bit == "1":
            # Addition step: only if the bit is 1
            target_Point = add_points_proj(target_Point, G, prime)

    return to_affine(target_Point, prime)

if __name__ == "__main__":
    # Parameters for secp256k1 curve
    a = 0
    b = 7
    G = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424, 1)
    prime = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
    n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    start_time = time.time()

    # At the Signer side, First of all we have to calculate the private and the public key
    # (d) represent the Pravite key for Alice (which wants to sign a message)
    #d = 74690464879392750132431713492634027726446507878980417043619012277907993413615 #for example, chosen randomly from the range [1, n-1]
    d = random.getrandbits(256)

    print(f"Private key length: {d.bit_length()} bits")

    # (Q) represent her public which equal to (d*G)
    Q = montgomery_ladder_proj(G=G, k=d, n=n, prime=prime)

    print(f"Public key (X coordinate) length: {Q[0].bit_length()} bits")
    print(f"Public key (Y coordinate) length: {Q[1].bit_length()} bits")
    print(f"Note: The code does not account for the leading zeros of the key, which means its bit length may be slightly less than 256 bits.")

    key_gen_time = time.time() - start_time
    print(f"Key Generation Time: {key_gen_time:.6f} seconds")
    print(f"------------------------------------------------")

    # Measure memory after key generation
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage after key generation: {current / 1024:.2f} KB")
    print(f"Peak memory usage after key generation: {peak / 1024:.2f} KB")
    print(f"------------------------------------------------")

    print(f"On the Signer's side:")
    print(f"---------------------")

    # 1. Calculate e = H(m);
    message = input("Please enter the message to be signed: ").encode('utf-8')
    hash_hex = hashlib.sha256(message).hexdigest()
    e = int(hash_hex, 16)

    # 2. Select a nonce integer “random_key” randomly from the range [1, n-1];
    Nonce = random.getrandbits(256)

    # 3. Calculate random_point = random_key * G = (x1, y1);
    start_time = time.time()
    random_point = montgomery_ladder_proj(G=G, k=Nonce, n=n, prime=prime)

    # 4. Calculate r ≡ x1 (mod n);
    r = (random_point[0]) % n # random_point[0] represent the x-coordinate of the point random_key * G = (x1, y1)
    s = ((e + r * d) * pow (Nonce, n - 2, n)) % n
    signing_time = time.time() - start_time
    print(f"Signing Time: {signing_time:.6f} seconds")

    # Measure memory after signing
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage after signing: {current / 1024:.2f} KB")
    print(f"Peak memory usage after signing: {peak / 1024:.2f} KB")

    print(f"Message: {message.decode('utf-8')}")
    print(f"Signature (r, s): ({r}, {s})")
    print(f"The signer will now send the signature components r and s, along with the message, to the verifier.")
    print(f"-->")
    # Alice now sends the signature (r, s) to Bob
    
    #Verification sign by Bob
    print(f"On the receiver's side:")
    print(f"---------------------")
    # 1. Calculate e = H(m);
    message = input("Enter the message as it was received by the Verifier to check if the signature is valid : ").encode('utf-8')
    hash_hex = hashlib.sha256(message).hexdigest()
    e = int(hash_hex, 16)

    r = int(input("Enter (r) as it suppose to be received by the Verifier (use the same style): "))
    s = int(input("Enter (s) as it was received by the Verifier (use the same style) : "))

    # 2. Calculate u1≡ e*(s^(-1))(mod n) and u2≡ r(s^(-1))(mod n);
    start_time = time.time()
    s_inv = pow(s, n - 2, n)
    u1 = (e * s_inv) % n
    u2 = (r * s_inv) % n
    u1 = Binary_method_proj(G=G, k=u1, n=n, prime=prime)
    u2 = Binary_method_proj(G=(Q[0], Q[1], 1), k=u2, n=n, prime=prime)
    u1_proj = (u1[0], u1[1], 1)
    u2_proj = (u2[0], u2[1], 1)

    #u1 + u2
    checkpoint = add_points_proj(u1_proj,u2_proj, prime)
    checkpoint = to_affine(checkpoint, prime)
    verification_time = time.time() - start_time
    print(f"Verification Time: {verification_time:.6f} seconds")

    # Measure memory after verification
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage after verification: {current / 1024:.2f} KB")
    print(f"Peak memory usage after verification: {peak / 1024:.2f} KB")

    if (checkpoint[0]) == r:
        print("The signature is valid")
    else:
        print("The signature refused")

    # Display final memory usage and stop memory tracking
    current, peak = tracemalloc.get_traced_memory()
    print(f"Final Current memory usage: {current / 1024:.2f} KB")
    print(f"Final Peak memory usage: {peak / 1024:.2f} KB")

    tracemalloc.stop()
