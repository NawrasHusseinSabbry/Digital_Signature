# The 288 byte message that we signed and verified in our test in our research is:  
# The wisdom of today: Surround yourself with people whose eyes light 
# up when they see you coming, and slowly is the fastest way to get to 
# where you want to be, the top of one mountain is the bottom of the next _ so keep climbing.
import random
import hashlib
import time
import tracemalloc

def hashing(message_int):
    return int(hashlib.sha256(str(message_int).encode("utf-8")).hexdigest(), 16)

def text2int(text):
    encode_text = text.encode("utf-8")
    hex_text = encode_text.hex()
    return int(hex_text, 16)

def add_points_projective(P, Q, a, d, prime):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    
    A = (Z1 * Z2) % prime
    B = (A * A) % prime
    C = (X1 * X2) % prime
    D = (Y1 * Y2) % prime
    E = (d * C * D) % prime
    F = (B - E) % prime
    G = (B + E) % prime

    X3 = (A * F * ((X1 + Y1) * (X2 + Y2) % prime - C - D) % prime) % prime
    Y3 = (A * G * (D - a * C)) % prime
    Z3 = (F * G) % prime

    return X3, Y3, Z3

def double_point_projective(P, a, prime):
    X1, Y1, Z1 = P
    
    B = ((X1 + Y1) * (X1 + Y1)) % prime
    C = (X1 * X1) % prime
    D = (Y1 * Y1) % prime
    E = (a * C) % prime
    F = (E + D) % prime
    H = (Z1 * Z1) % prime
    J = (F - (2 * H)) % prime

    X3 = ((B - C - D) * J) % prime
    Y3 = (F * (E - D)) % prime
    Z3 = (F * J) % prime

    return X3, Y3, Z3

def cswap(swap, P, Q, prime):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q

    dummy_X = swap * ((X1 - X2) % prime)
    dummy_Y = swap * ((Y1 - Y2) % prime)
    dummy_Z = swap * ((Z1 - Z2) % prime)

    X1 = (X1 - dummy_X) % prime
    X2 = (X2 + dummy_X) % prime
    Y1 = (Y1 - dummy_Y) % prime
    Y2 = (Y2 + dummy_Y) % prime
    Z1 = (Z1 - dummy_Z) % prime
    Z2 = (Z2 + dummy_Z) % prime

    return (X1, Y1, Z1), (X2, Y2, Z2)

def montgomery_ladder_ed25519(G, k, a, d, prime):
    R1 = G
    R0 = double_point_projective(G, a, prime)

    k_binary = bin(k)[2:]
    swap = 1

    for i in range(1, len(k_binary)):
        bit = int(k_binary[i])
        swap ^= bit

        R0, R1 = cswap(swap, R0, R1, prime)
        swap = bit

        R1 = add_points_projective(R0, R1, a, d, prime)
        R0 = double_point_projective(R0, a, prime)

    R0, R1 = cswap(swap, R0, R1, prime)

    return R0

def Binary_method_projective(G, k, a, d, prime):
    target_point = G
    k_binary = bin(k)[2:]

    for i in range(1, len(k_binary)):
        current_bit = k_binary[i:i+1]

        target_point = double_point_projective(target_point, a, prime)

        if current_bit == "1":
            target_point = add_points_projective(target_point, G, a, d, prime)

    return target_point

def to_affine(P, prime):
    X, Y, Z = P
    Z_inv = pow(Z, prime-2, prime)  # Using Fermat's Little Theorem for modular inverse
    X_affine = (X * Z_inv) % prime
    Y_affine = (Y * Z_inv) % prime

    return X_affine, Y_affine

def to_projective(P):
    X, Y = P
    return X, Y, 1

if __name__ == "__main__":
    prime = pow(2, 255) - 19
    a = -1
    d = (-121665 * pow(121666, prime-2, prime)) % prime
    
    # Base point G in projective coordinates (X:Y:Z) with Z = 1
    u = 9
    Gy = ((u-1) * pow(u+1, prime-2, prime))
    Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    G = (Gx, Gy, 1)

    # Measure key length
    key_length = 256  # in bits
    print(f"Key length: {key_length} bits")

    # Start memory tracking
    tracemalloc.start()

    # Signing Operation
    print(f" ")
    message = input("Enter the message to sign: ")
    message_int = text2int(message)
    print(f" ")

    #1. Select a Private Key (secret key “Sk”)
    private_key = random.getrandbits(256)
    print(f"Private Key = {private_key}")
    print(f" ")

    # Measure time for public key calculation
    start_time = time.time()
    public_key = to_affine(montgomery_ladder_ed25519(G, private_key, a, d, prime), prime)
    end_time = time.time()
    print(f"Public Key = {public_key}")
    print(f"Time taken for public key calculation: {end_time - start_time:.6f} seconds")
    print(f" ")

    # Measure time for signing
    start_time = time.time()
    h = hashing(private_key)
    r = (hashing(text2int(str(h) + str(message_int)))) % prime
    R_projective = montgomery_ladder_ed25519(G, r, a, d, prime)
    R = to_affine(R_projective, prime)
    h = (hashing(text2int(str(R[0]) + str(public_key[0]) + str(message_int)))) % prime
    s = r + h * private_key
    end_time = time.time()

    print(f"The Signer will send the message and the Signature (R, s) to the Verifier ")
    print(f"R={R}")
    print(f"s={s}")
    print(f"Time taken for signing: {end_time - start_time:.6f} seconds")
    print(f" ")

    # Measure peak memory usage
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage: {current / 1024:.2f} KB")
    print(f"Peak memory usage: {peak / 1024:.2f} KB")

    # Verification Operation
    print(f"======================== Verification operation at the receiver side:")
    print(f" ")

    # Start memory tracking for verification
    tracemalloc.start()

    received_message = input("Enter the message received: ")
    received_message_int = text2int(received_message)
    print(f" ")
    received_R_x = int(input("Enter the The x-coordinate of the public nonce R.x received: "))
    received_R_y = int(input("Enter the The y-coordinate of the public nonce R.y received: "))
    received_s = int(input("Enter the s received: "))
    received_R = (received_R_x, received_R_y)

    # Measure time for verification
    start_time = time.time()
    h = (hashing(text2int(str(received_R[0]) + str(public_key[0]) + str(received_message_int)))) % prime
    V1_projective = Binary_method_projective(G, received_s, a, d, prime)
    V1 = to_affine(V1_projective, prime)
    V2_projective = add_points_projective(to_projective(received_R), Binary_method_projective(to_projective(public_key), h, a, d, prime), a, d, prime)
    V2 = to_affine(V2_projective, prime)
    end_time = time.time()

    print(f"V1 = {V1}")
    print(f"V2 = {V2}")
    print(f"Time taken for verification: {end_time - start_time:.6f} seconds")

    if V1 == V2:
        print(f"The Signature is valid")
    else:
        print(f"The signature is invalid")

    # Measure peak memory usage for verification
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage during verification: {current / 1024:.2f} KB")
    print(f"Peak memory usage during verification: {peak / 1024:.2f} KB")

    # Stop memory tracking
    tracemalloc.stop()
