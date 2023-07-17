import struct
import timeit


def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def padding(message):
    message_length = len(message)
    padding_length = (64 - (message_length + 8) % 64) % 64
    padding = b'\x80' + b'\x00' * (padding_length - 1)
    length_bits = (message_length * 8).to_bytes(8, byteorder='big')
    return message + padding + length_bits


def sm3(message):
    message = padding(message)
    message_length = len(message)

    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

    Tj = [0x79CC4519, 0x7A879D8A] * 16 + [0x8F1BBCDC, 0x390E5C25] * 16 + [0x9D8A7A87, 0x7A879D8A] * 16 + \
         [0x3C6EF372, 0x2A54FF53] * 16 + [0x7C54A8AC, 0x6CBCE3EB] * 16 + [0x9FBDCBF1, 0x1B3CDCD1] * 16 + \
         [0x8A7A879D, 0x8780A3D2] * 16 + [0x00000000, 0x00000000]

    V = IV[:]
    W = [0] * 68

    for i in range(0, message_length, 64):
        chunk = message[i:i+64]
        W[:16] = [struct.unpack('>I', chunk[j*4:j*4+4])[0] for j in range(16)]

        for j in range(16, 68):
            W[j] = left_rotate(W[j-16] ^ W[j-9] ^ (left_rotate(W[j-3], 15)), 7) ^ (left_rotate(W[j-13], 7)) ^ W[j-6]

        W_ = [W[j] ^ W[j+4] for j in range(64)]

        A, B, C, D, E, F, G, H = V[:]

        for j in range(64):
            SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(Tj[j], j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ left_rotate(A, 12)
            TT1 = (A ^ B ^ C) + D + SS2 + W_[j]
            TT2 = (E ^ F ^ G) + H + SS1 + W[j]

            D, C, B, A, H, G, F, E = C, left_rotate(B, 9), A, TT1, G, left_rotate(F, 19), E, (TT2 + left_rotate(E, 6)) & 0xFFFFFFFF

        V = [(V[i] ^ A) & 0xFFFFFFFF for i in range(8)]

    hash_value = b''.join([struct.pack('>I', v) for v in V])
    return hash_value.hex()


# 测试运行时间
message = b'This is a test message.'
time = timeit.timeit(lambda: sm3(message), number=1000)
print('Hash:', sm3(message))
print('Time:', time, 'seconds')
