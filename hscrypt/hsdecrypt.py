import hashlib
import argparse

parser = argparse.ArgumentParser(description="MD5 Cracker")
parser.add_argument("-hash", dest="hash", help="md5 hash")
parser.add_argument("-w", dest="wordlist", help="wordlist", required=True)
parsed_args = parser.parse_args()


def main():
    hash_decrypt = ""
    args = ["md5",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha512",
            "sha3_224",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "blake2s",
            "blake2b"]
    hashes = [hashlib.md5, hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512,
              hashlib.sha3_224, hashlib.sha3_256, hashlib.sha3_384, hashlib.sha3_512, hashlib.blake2s,
              hashlib.blake2b]
    with open(parsed_args.wordlist) as file:
        for line in file:
            line = line.strip()
            for hash, arg in zip(hashes, args):
                if hash(bytes(line, encoding="utf-8")).hexdigest() == parsed_args.hash:
                    hash_cracked = line
                    print("Hashed : " + arg.upper() + "\nThe password is : %s" % line)


if __name__ == "__main__":
    main()
