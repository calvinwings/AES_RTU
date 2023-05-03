 Marshall Calvin StudentID : 221ADM071

#Convert the plaintext and key into lists of their corresponding ASCII values.
#Perform key expansion to generate the round keys.
#Divide the plaintext into a 4x4 array called the "state".
#Add the first round key to the state.
#For each of the 9 rounds:
#a. Substitute each byte in the state with its corresponding value from the S-box.
#b. Shift the rows of the state to the left.
#c. Mix the columns of the state.
#d. Add the round key for the current round to the state.
#For the last round:
#a. Substitute each byte in the state with its corresponding value from the S-box.
#b. Shift the rows of the state to the left.
#c. Add the final round key to the state.
#Convert the resulting state back into a list of ASCII values, and concatenate them to form the ciphertext.
#AES Decryption:

#Convert the ciphertext and key into lists of their corresponding ASCII values.
#Perform key expansion to generate the round keys.
#Divide the ciphertext into a 4x4 array called the "state".
#Add the final round key to the state.
#For each of the 9 rounds (in reverse order):
#a. Shift the rows of the state to the right.
#b. Substitute each byte in the state with its corresponding value from the inverse S-box.
#c. Add the round key for the current round to the state.
#d. Mix the columns of the state.
#For the last round:
#a. Shift the rows of the state to the right.
#b. Substitute each byte in the state with its corresponding value from the inverse S-box.
#c. Add the first round key to the state.
#Convert the resulting state back into a list of ASCII values, and concatenate them to form the plaintext.


from tkinter import *
from math import ceil



# Key Expansion
def key_expansion(key):
    # Rijndael round constants
    rcon = [[0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
            [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]]
    # Convert the key to a list of 32-bit words
    w = [[key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]] for i in range(4)]
    # Expand the key into an array of 44 words
    for i in range(4, 4 * 11):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = [temp[1], temp[2], temp[3], temp[0]]
            temp = [sbox[byte] for byte in temp]
            temp[0] ^= rcon[i // 4 - 1][0]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return w

# SubBytes Transformation
def sub_bytes(state):
    return [[sbox[byte] for byte in row] for row in state]

# ShiftRows Transformation
def shift_rows(state):
    return [state[row][row:] + state[row][:row] for row in range(4)]

# MixColumns Transformation
def mix_columns(state):
    def mix_single_column(column):
        r = [xtime(column[i]) ^ xtime(column[(i + 1) % 4]) ^ column[(i + 2) % 4] ^ column[(i + 3) % 4] for i in range(4)]
        return r

    return [mix_single_column(state[i]) for i in range(4)]

# AddRoundKey Transformation
def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

# AES Encryption
def aes_encrypt(plaintext, key):
    plaintext = [ord(char) for char in plaintext]
    key = [ord(char) for char in key]
    w = key_expansion(key)
    state = [plaintext[i:i + 4] for i in range(0, len(plaintext), 4)]
    state = add_round_key(state, w[:4])
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, w[4 * i:4 * (i + 1)])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, w[40:44])
    ciphertext = [byte for row in state for byte in row]
    return ''.join([chr(byte) for byte in ciphertext])




# You can use this function to decrypt the ciphertext generated using the aes_encrypt function. Note that you need to use the same key for encryption and decryption.

# Inverse SubBytes Transformation
def inv_sub_bytes(state):
    return [[inv_sbox[byte] for byte in row] for row in state]

# Inverse ShiftRows Transformation
def inv_shift_rows(state):
    return [state[row][-row:] + state[row][:-row] for row in range(4)]

# Inverse MixColumns Transformation
def inv_mix_columns(state):
    def inv_mix_single_column(column):
        r = [
            xtime(xtime(xtime(column[i] ^ column[(i + 2) % 4]))) ^ xtime(xtime(column[(i + 1) % 4] ^ column[(i + 3) % 4])) ^ column[i] ^ column[(i + 1) % 4] ^ column[(i + 2) % 4] ^ column[(i + 3) % 4]
            for i in range(4)
        ]
        return r

    return [inv_mix_single_column(state[i]) for i in range(4)]

# AES Decryption
def aes_decrypt(ciphertext, key):
    ciphertext = [ord(char) for char in ciphertext]
    key = [ord(char) for char in key]
    w = key_expansion(key)
    state = [ciphertext[i:i + 4] for i in range(0, len(ciphertext), 4)]
    state = add_round_key(state, w[40:44])
    for i in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, w[4 * i:4 * (i + 1)])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, w[:4])
    plaintext = [byte for row in state for byte in row]
    return ''.join([chr(byte) for byte in plaintext])
