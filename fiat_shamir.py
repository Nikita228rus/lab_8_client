from conf_sha import *
from conf_math import *


def user(hash_func, size):
    message = open('input.txt', 'r', encoding='utf-8').read()

    if hash_func == '1':
        message_hash = sha_256(message)
        zero = 256

    elif hash_func == '2':
        message_hash = sha_512(message)
        zero = 512
    else:
        message_hash = None
        zero = 0

    p = generation_prime(size)
    q = generation_prime(size)
    n = p * q
    m = len(bin(int(message_hash, 16))[2:].zfill(zero))

    a = []
    b = []
    for i in range(m):
        a.append(random.randint(1, n))
        b.append(pow(reciprocal_integer(a[i], n), 2, n))

    _public_key_ = (b, n)
    _private_key_ = (a, p, q)

    r = random.randint(1, n - 1)
    u = pow(r, 2, n)
    u = str(u)
    s = bin(int(sha_256(message + u), 16))[2:].zfill(zero)

    t = 1
    for i in range(len(s)):
        t *= pow(a[i], int(s[i]))

    t = pow(r * t, 1, n)
    print(t)

    signature = (s, t)

    return signature, _public_key_, message


def server(signature, _public_key_, message):

    b = _public_key_[0]
    n = _public_key_[1]
    s = signature[0]
    t = signature[1]


    w = 1
    for i in range(len(s)):
        w *= pow(b[i], int(s[i]))

    w = pow(t * t * w, 1, n)
    print(w)
    w = str(w)
    s_check = bin(int(sha_256(message + w), 16))[2:].zfill(256)

    print(s == s_check)





s, p, m = user('1', 10)
server(s, p, m)

message = 'hello'
message_hash = bin(int(sha_256(message), 16))[2:].zfill(256)
m = len(message_hash)

p = generation_prime(10)
q = generation_prime(10)
n = generation_prime(128)

a = []
b = []

for i in range(m):
    a.append(random.randint(1, n - 1))
    b.append(pow(reciprocal_integer(a[i], n), 2, n))

r = random.randint(1, n - 1)
u = pow(r, 2, n)
s = bin(int(sha_256(message + str(u)), 16))[2:].zfill(256)
t = 1
for i in range(len(s)):
    t *= pow(a[i], int(s[i]))
t = pow(t * r, 1, n)


w = 1
for i in range(len(s)):
    w *= pow(b[i], int(s[i]))
w = pow(pow(t, 2) * w, 1, n)
print(u, w)

m = 5
n = 17

a = [5, 5, 4, 12, 2]
b = [15, 15, 16, 15, 13]
r = 7
s = '11111'

u = pow(r, 2, n)

t = 1
for i in range(m):
    t *= pow(a[i], int(s[i]))
t = pow(t * r, 1, n)

w = 1
for i in range(m):
    w *= pow(b[i], int(s[i]))
w = pow(t * t * w, 1, n)

print(u, w)