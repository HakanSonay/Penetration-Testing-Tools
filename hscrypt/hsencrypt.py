import argparse
import hashlib

parser = argparse.ArgumentParser(description='ENCRYPT')
parser.add_argument('-md5', help="md5 hash", action='store_true')
parser.add_argument('-sha1', help="sha1 hash", action='store_true')
parser.add_argument('-sha224', help="sha224 hash", action='store_true')
parser.add_argument('-sha256', help="sha256 hash", action='store_true')
parser.add_argument('-sha384', help="sha384 hash", action='store_true')
parser.add_argument('-sha512', help="sha512 hash", action='store_true')
parser.add_argument('-sha3_224', help="sha3_224 hash", action='store_true')
parser.add_argument('-sha3_256', help="sha3_256 hash", action='store_true')
parser.add_argument('-sha3_384', help="sha3_384 hash", action='store_true')
parser.add_argument('-sha3_512', help="sha3_512 hash", action='store_true')
parser.add_argument('-blake2s', help="blake2s hash", action='store_true')
parser.add_argument('-blake2b', help="blake2b hash", action='store_true')
parser.add_argument('-all', help="all encode", action='store_true')
parser.add_argument('-w', dest="word", help="word", required=True)
parsed_args = parser.parse_args()

if parsed_args.md5:
    result = hashlib.md5(parsed_args.word.encode())
    print("MD5 : " + result.hexdigest())

if parsed_args.sha1:
    result = hashlib.sha1(parsed_args.word.encode())
    print("SHA1 : " + result.hexdigest())

if parsed_args.sha224:
    result = hashlib.sha224(parsed_args.word.encode())
    print("SHA224 : " + result.hexdigest())

if parsed_args.sha256:
    result = hashlib.sha256(parsed_args.word.encode())
    print("SHA256 : " + result.hexdigest())

if parsed_args.sha384:
    result = hashlib.sha384(parsed_args.word.encode())
    print("SHA384 : " + result.hexdigest())

if parsed_args.sha512:
    result = hashlib.sha512(parsed_args.word.encode())
    print("SHA512 : " + result.hexdigest())

if parsed_args.sha3_224:
    result = hashlib.sha3_224(parsed_args.word.encode())
    print("SHA3_224 : " + result.hexdigest())

if parsed_args.sha3_256:
    result = hashlib.sha3_256(parsed_args.word.encode())
    print("SHA3_256 : " + result.hexdigest())

if parsed_args.sha3_384:
    result = hashlib.sha3_384(parsed_args.word.encode())
    print("SHA3_384 : " + result.hexdigest())

if parsed_args.sha3_512:
    result = hashlib.sha3_512(parsed_args.word.encode())
    print("SHA3_512 : " + result.hexdigest())

if parsed_args.blake2s:
    result = hashlib.blake2s(parsed_args.word.encode())
    print("BLAKE2S : " + result.hexdigest())

if parsed_args.blake2b:
    result = hashlib.blake2b(parsed_args.word.encode())
    print("BLAKE2B : " + result.hexdigest())

if parsed_args.all:
    hashes = [hashlib.md5, hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512,
              hashlib.sha3_224, hashlib.sha3_256, hashlib.sha3_384, hashlib.sha3_512, hashlib.blake2s,
              hashlib.blake2b]
    for hash, arg in zip(hashes, parsed_args.__dict__):
        result = hash(parsed_args.word.encode())
        print(arg.upper() + " : " + result.hexdigest())
