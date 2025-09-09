import sys
import struct

SHA3_256_RATE_BITS = 1088
SHA3_OUTPUT_LEN = 256
ROUND_NUM = 24

STATE = 1600
STATE_IN_BYTES = 200  # STATE // 8
LANE_SIZE_BITS = 64
LANE_SIZE_BYTES = 8 # LANE_SIZE_BITS // 8

MATRIX_DIM = 5

# Costanti di rotazione per rho
ROTATION_CONSTANTS = (
#   y=0 y=1 y=2 y=3 y=4
    (0, 36, 3, 41, 18),    # x=0
    (1, 44, 10, 45, 2),    # x=1
    (62, 6, 43, 15, 61),   # x=2
    (28, 55, 25, 21, 56),  # x=3
    (27, 20, 39, 8, 14)    # x=4
)

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

def padding(message_bytes: bytes, rate_in_bits: int, suffix: int = 0x06) -> bytes:
    rate_in_bytes = rate_in_bits // 8
    m = bytearray(message_bytes)
    m.append(suffix)

    # 2) zeri fino a lasciare l'ultima byte del blocco libera
    zeros = (-len(m) - 1) % rate_in_bytes
    if zeros:
        m.extend(b'\x00' * zeros)
    m.append(0x80)
    return bytes(m)


def divide_into_blocks(padded_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    rate_in_bytes = rate_in_bits // 8
    blocks = []
    for i in range(0, len(padded_bytes), rate_in_bytes):
        block = padded_bytes[i:i + rate_in_bytes]
        blocks.append(block)
    return blocks

def pre_processing(message_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    padded_message = padding(message_bytes, rate_in_bits)
    blocks = divide_into_blocks(padded_message, rate_in_bits)
    return blocks

def bytes_to_lanes(byte_data: bytearray) -> list[int]:
    return list(struct.unpack('<25Q', byte_data))

def lanes_to_bytes(lanes: list[int]) -> bytearray:
    return bytearray(struct.pack('<25Q', *lanes))

def theta(A: list[list[int]]) -> None:
    C = [0] * MATRIX_DIM
    D = [0] * MATRIX_DIM

    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            C[x] ^= A[x][y]

    for x in range(MATRIX_DIM):
        D[x] = C[(x - 1) % MATRIX_DIM] ^ ((C[(x + 1) % MATRIX_DIM] << 1) | (C[(x + 1) % MATRIX_DIM] >> (64 - 1))) & 0xFFFFFFFFFFFFFFFF

    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A[x][y] ^= D[x]

def rho(A: list[list[int]]) -> None:
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            shift = ROTATION_CONSTANTS[x][y]
            A[x][y] = ((A[x][y] << shift) | (A[x][y] >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF

def pi(A: list[list[int]]) -> None:
    temp = [[A[x][y] for y in range(MATRIX_DIM)] for x in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A[x][y] = temp[(x + 3 * y) % MATRIX_DIM][x]

def chi(A: list[list[int]]) -> None:
    for y in range(MATRIX_DIM):
        temp_row = [A[x][y] for x in range(MATRIX_DIM)]
        for x in range(MATRIX_DIM):
            A[x][y] ^= (~temp_row[(x + 1) % MATRIX_DIM] & temp_row[(x + 2) % MATRIX_DIM])

def iota(A: list[list[int]], round_index: int) -> None:
    A[0][0] ^= ROUND_CONSTANTS[round_index]

def keccak_f(state: bytearray) -> bytearray:
    lanes = bytes_to_lanes(state)
    # prepara la matrice 5x5
    A = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A[x][y] = lanes[x + MATRIX_DIM*y]

    # 24 round
    for round_index in range(ROUND_NUM):
        theta(A)
        rho(A)
        pi(A)
        chi(A)
        iota(A, round_index)

    # riconverte la matrice
    lanes_flat = []
    for y in range(MATRIX_DIM):
        for x in range(MATRIX_DIM):
            lanes_flat.append(A[x][y])

    return lanes_to_bytes(lanes_flat)

def absorbing(state: bytearray, blocks: list[bytes], rate_in_bytes: int) -> bytearray:
    for block in blocks:
        for i in range(rate_in_bytes):
            state[i] ^= block[i]
        state = keccak_f(state)
    return state

def squeezing(state: bytearray, rate_in_bytes: int, output_len_bits: int) -> bytes:
    output_len_bytes = output_len_bits // 8
    return bytes(state[:output_len_bytes])

def sponge_construction(blocks: list[bytes], rate_in_bits: int, output_len_bits: int) -> bytes:
    state = bytearray(STATE_IN_BYTES)
    rate_in_bytes = rate_in_bits // 8
    state = absorbing(state, blocks, rate_in_bytes)
    return squeezing(state, rate_in_bytes, output_len_bits)

def sha3_256(message: bytes) -> bytes:
    blocks = pre_processing(message, SHA3_256_RATE_BITS)
    return sponge_construction(blocks, SHA3_256_RATE_BITS, SHA3_OUTPUT_LEN)

def process_file(filename: str):
    try:
        with open(filename, "rb") as f:
            message = f.read()
    except FileNotFoundError:
        print(f"Error: file not found '{filename}'")
        return
    hash_result = sha3_256(message)
    print(f"SHA3-256({filename})= {hash_result.hex()}")

def main():
    if len(sys.argv) > 1:
        for filename in sys.argv[1:]:
            process_file(filename)
    else:
        message = sys.stdin.buffer.read()
        hash_result = sha3_256(message)
        print(f"SHA3-256(stdin)= {hash_result.hex()}")

if __name__ == '__main__':
    main()
