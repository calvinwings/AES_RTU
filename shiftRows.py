# Marshall Calvin StudentID : 221ADM071


# Github link https://github.com/calvinwings/AES_RTU

def rotate(word, n):
    return word[n:] + word[0:n]

def shiftRows(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4], i)

def shiftRowsInv(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4], -i)

state = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
shiftRows(state)
print(state)

shiftRowsInv(state)
print(state)


