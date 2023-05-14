# Marshall Calvin StudentID : 221ADM071


# Github link https://github.com/calvinwings/AES_RTU

def addRoundKey(state, roundKey):
    for i in range(len(state)):
        state[i] = state[i] ^ roundKey[i]

state=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
roundkey=[2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1]

addRoundKey(state,roundkey)

print(state)

addRoundKey(state,roundkey)

print(state)