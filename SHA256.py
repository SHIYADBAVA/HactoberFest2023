import math

# Helper functions for SHA-256
def right_rotate(num, bits):
    return ((num >> bits) | (num << (32 - bits))) & 0xFFFFFFFF

def sha256_padding(message):
    original_length = len(message) * 8
    # Append a single '1' bit to the message
    message += b'\x80'
    # Append '0' bits until the message length in bits ≡ 448 (mod 512)
    message += b'\x00' * ((56 - len(message) % 64) % 64)
    # Append the original length in bits as a 64-bit big-endian integer
    message += original_length.to_bytes(8, 'big')
    return message

def sha256(message):
    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    # Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Pre-processing (padding)
    message = sha256_padding(message)

    # Process the message in blocks of 512 bits
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        w = [0] * 64

        # Break the block into 16 big-endian 32-bit words
        for j in range(16):
            w[j] = int.from_bytes(block[j*4:j*4+4], 'big')

        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for j in range(16, 64):
            s0 = right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

        # Initialize hash value for this chunk
        a, b, c, d, e, f, g, h = h

        # Main loop
        for j in range(64):
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[j] + w[j]

            # Update hash values
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # Add this chunk's hash to the result so far
        h = (h + a) & 0xFFFFFFFF
        g = (g + b) & 0xFFFFFFFF
        f = (f + c) & 0xFFFFFFFF
        e = (e + d) & 0xFFFFFFFF
        d = (d + e) & 0xFFFFFFFF
        c = (c + f) & 0xFFFFFFFF
        b = (b + g) & 0xFFFFFFFF
        a = (a + h) & 0xFFFFFFFF

    # Produce the final hash value as a 256-bit (32-byte) hexadecimal number
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (a, b, c, d, e, f, g, h)

# Example usage
message = "Hello, SHA-256!"
hashed_message = sha256(message.encode('utf-8'))
print("SHA-256 Hash:", hashed_message)
