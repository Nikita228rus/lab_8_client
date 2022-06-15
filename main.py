from datetime import datetime
from conf_sha import *
from conf_math import *
import json


def generation_key(size):
    _public_key_ = {
        'SubjectPublickeyInfo': {
            'alpha': None,
            'beta': None,
            'p': None,
        }
    }
    _private_key_ = {
        'privateExponent': None
    }
    p = generation_prime(size)
    alfa = parent_element(p)
    a = random.randint(1, p - 2)
    beta = pow(alfa, a, p)

    _public_key_['SubjectPublickeyInfo']['alpha'] = alfa
    _public_key_['SubjectPublickeyInfo']['beta'] = beta
    _public_key_['SubjectPublickeyInfo']['p'] = p
    _private_key_['privateExponent'] = a

    json.dump(_public_key_, open('PKCS8.json', 'w+'), indent=4)
    json.dump(_private_key_, open('PKCS12.json', 'w+'), indent=4)


def user(hash_func, size):
    _document_ = {
        'CMSVersion': 1,
        'DigestAlgorithmIdentifiers': 'sha-256',
        'EncapsulatedContentInfo': {'ContentType': 'text',
                                    'OCTET STRING OPTIONAL': 'исходный текст',
                                    },
        'CertificateSet OPTIONAL': 'открытый ключ',
        'RevocationInfoChoises OPTIONAL': None,
        'SignerInfos': {
            'CMSVersion': 1,
            'SignerIdentifier': 'Nikich228rus',
            'DigestAlgorithmIdentifier': 'sha-256',
            'SignedAttributes OPTIONAL': None,
            'SignatureAlgorithmIdentifier': 'RSAdsi',
            'SignatureValue': 'h(m)^d1 mod n',
            'UnsignedAttributes OPTIONAL': {
                'OBJECT IDENTIFIER': 'signature-time-stamp',
                'SET OF AttributeValue': None
            }
        }
    }

    message = open('input.txt', 'r', encoding='utf-8').read()
    _document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL'] = message
    generation_key(size)

    if hash_func == '1':
        message_hash = sha_256(message)
        _document_['SignerInfos']['DigestAlgorithmIdentifier'] = 'sha-256'

    elif hash_func == '2':
        message_hash = sha_512(message)
        _document_['SignerInfos']['DigestAlgorithmIdentifier'] = 'sha-512'

    else:
        message_hash = None

    _public_key_ = json.load(open('PKCS8.json', 'r'))
    _private_key_ = json.load(open('PKCS12.json', 'r'))

    p = _public_key_['SubjectPublickeyInfo']['p']
    alfa = _public_key_['SubjectPublickeyInfo']['alpha']
    beta = _public_key_['SubjectPublickeyInfo']['beta']
    a = _private_key_['privateExponent']

    r = random.randint(1, p - 2)
    while euclid_algorithm(r, p - 1, False)[0] != 1:
        r = random.randint(1, p - 2)

    r_1 = reciprocal_integer(r, p - 1)

    gama = pow(alfa, r, p)
    message_int = text_to_int(message_hash)

    delta = pow((message_int - a * gama) * r_1, 1, p - 1)
    signature = (gama, delta)

    _document_['SignerInfos']['SignatureValue'] = signature
    _document_['CertificateSet OPTIONAL'] = [alfa, beta, p]
    json.dump(_document_, open('PKCS_send.json', 'w+'), indent=4)

    send_file = str(json.load(open('PKCS_send.json', 'r')))
    client_send(send_file)


    _data_ = json.load(open('PKCS_get.json', 'r'))
    gama, delta = _data_['signature centre']
    alfa, beta, p = _data_['public key']
    time_stamp = _data_['time-stamp']

    if hash_func == '1':
        message_time = sha_256(message + time_stamp)
    elif hash_func == '2':
        message_time = sha_512(message + time_stamp)
    else:
        message_time = None

    message_int = text_to_int(message_time)

    if pow(pow(beta, gama) * pow(gama, delta), 1, p) == pow(alfa, message_int, p):
        print('All ok')
        _document_['SignerInfos']['UnsignedAttributes OPTIONAL']['OBJECT IDENTIFIER'] = _data_['signature centre']
        _document_['SignerInfos']['UnsignedAttributes OPTIONAL']['SET OF AttributeValue'] = time_stamp
        json.dump(_document_, open('PKCS_send.json', 'w+'), indent=4)
    else:
        print('Error')


def centre_time():

    _data_result_ = {
        'signature centre': None,
        'public key': None,
        'time-stamp': None,
    }
    _document_ = json.load(open('PKCS_send.json', 'r', encoding='utf-8'))
    gama = _document_['SignerInfos']['SignatureValue'][0]
    delta = _document_['SignerInfos']['SignatureValue'][1]

    alfa, beta, p = _document_['CertificateSet OPTIONAL']
    message = _document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL']
    message_int = text_to_int(message)

    size = len(bin(p)[2:])
    hash_func = _document_['DigestAlgorithmIdentifiers']

    if pow(pow(beta, gama) * pow(gama, delta), 1, p) == pow(alfa, message_int, p):

        time_stamp = str(datetime.now())
        generation_key(size)

        _public_key_ = json.load(open('PKCS8.json', 'r'))
        _private_key_ = json.load(open('PKCS12.json', 'r'))

        p = _public_key_['SubjectPublickeyInfo']['p']
        alfa = _public_key_['SubjectPublickeyInfo']['alpha']
        beta = _public_key_['SubjectPublickeyInfo']['beta']
        a = _private_key_['privateExponent']

        if hash_func == 'sha-256':
            message_hash = sha_256(message + time_stamp)

        elif hash_func == 'sha-512':
            message_hash = sha_512(message + time_stamp)

        else:
            message_hash = None

        r = random.randint(1, p - 2)
        while euclid_algorithm(r, p - 1, False)[0] != 1:
            r = random.randint(1, p - 2)

        r_1 = reciprocal_integer(r, p - 1)

        gama = pow(alfa, r, p)
        message_int = text_to_int(message_hash)

        delta = pow((message_int - a * gama) * r_1, 1, p - 1)
        signature = (gama, delta)

        _data_result_['signature centre'] = signature
        _data_result_['public key'] = [alfa, beta, p]
        _data_result_['time-stamp'] = time_stamp
        json.dump(_data_result_, open('PKCS_get.json', 'w+'), indent=4)



#user('1', 5)




def parent_element(p):

    gf = [int(x) for x in range(1, p)]

    alfa = random.randint(1, p - 1)
    while pow(alfa, 2) % p == 1 or pow(alfa, int((p - 1) * 0.5), p) == 1:
        alfa = random.randint(1, p - 1)

    gf_check = []
    for i in range(p-1):
        gf_check.append(pow(alfa, i, p))
    gf_check.sort()

    if gf == gf_check:
        return alfa
    else:
        return parent_element(p)

p = generation_prime(1024)
print(parent_element(p))

