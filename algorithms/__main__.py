import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('args', help='input values for the cryptography module')
    parser.add_argument('--algorithm', choices=['kyber', 'rsa'], help='the algorithm to use', required=True)
    parser.add_argument('--public-key', '-p', help='output file name for the public key', type=str, required=True)
    parser.add_argument('--private-key', '-q', help='output file name for the private key', type=str, required=True)
    parser.add_argument('--strength', '-s', help='the strength of the algorithm', type=int, default=2)
    return parser.parse_args()

def main():
    args = parse_args()
    if args.algorithm == 'kyber':
        from kyber import Kyber
        kyber = Kyber()
        kyber.generate_keypair(args.strength)
        with open(args.public_key, 'wb') as f:
            f.write(kyber.public_key)
        with open(args.private_key, 'wb') as f:
            f.write(kyber.private_key)
        
    if args.algorithm == 'rsa':
        from rsa import RSA
        rsa = RSA()
        rsa.generate_keypair(args.strength)
        with open(args.public_key, 'wb') as f:
            f.write(rsa.public_key)
        with open(args.private_key, 'wb') as f:
            f.write(rsa.private_key)

if __name__ == '__main__':
    main()