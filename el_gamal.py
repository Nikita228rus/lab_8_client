from conf_sha import *
from conf_math import *


def user(hash_func, size):
    message = open('input.txt', 'r', encoding='utf-8').read()

    if hash_func == '1':
        message_hash = sha_256(message)

    elif hash_func == '2':
        message_hash = sha_512(message)

    else:
        message_hash = None

    p = generation_prime(size)
    alfa = parent_element(p)
    a = random.randint(1, p - 2)
    beta = pow(alfa, a, p)

    _public_key_ = [alfa, beta, p]
    _private_key_ = [a]

    r = random.randint(1, p - 2)
    while euclid_algorithm(r, p - 1, False)[0] != 1:
        r = random.randint(1, p - 2)

    """!!!"""
    r_1 = euclid_algorithm(r, p - 1, False)[1]
    while r_1 < 0:
        r_1 += (p - 1)
    """!!!"""

    gama = pow(alfa, r, p)
    message_int = text_to_int(message_hash)

    delta = pow((message_int - a * gama) * r_1, 1, p - 1)
    signature = (gama, delta)
    return signature, _public_key_, message_int


def server(signature, _public_key_, message_int):
    gama = signature[0]
    delta = signature[1]

    alfa = _public_key_[0]
    beta = _public_key_[1]
    p = _public_key_[2]

    print(pow(pow(beta, gama) * pow(gama, delta), 1, p) == pow(alfa, message_int, p))


s, p, m = user('1', 5)

server(s, p, m)

