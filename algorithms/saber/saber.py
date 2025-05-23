import random


class Saber:
    def __init__(self):
        self.q = 8192
        self.p = 1024
        self.n = 256
        self.l = 3
        self.eta = 4 

        self._generated = False
        self._pubkey = None
        self._privkey = None

    def _sample_noise_poly(self):
        return [
            sum(random.getrandbits(1) for _ in range(self.eta)) -
            sum(random.getrandbits(1) for _ in range(self.eta))
            for _ in range(self.n)
        ]
        
    def _round_message(self, m):
        return (m * (self.q // self.p)) % self.q

    def _recover_message(self, x):
        return int((x * self.p + self.q // 2) // self.q) % self.p

    def _poly_add(self, a, b):
        return [(x + y) % self.q for x, y in zip(a, b)]
    
    def _encode_message(self, message: str):
        bits = []
        for c in message.encode('utf-8'):
            bits += [(c >> i) & 1 for i in range(8)]
        return bits
    
    def _decode_message(self, bits):
        bytes_out = []
        for i in range(0, len(bits), 8):
            byte = sum([bits[i + j] << j for j in range(8) if i + j < len(bits)])
            bytes_out.append(byte)
        return bytes(bytes_out).decode('utf-8', errors='ignore')

    def _poly_mul(self, a, b):
        res = [0] * (2 * self.n - 1)
        for i in range(self.n):
            for j in range(self.n):
                res[i + j] += a[i] * b[j]
        for i in range(self.n, 2 * self.n - 1):
            res[i - self.n] = (res[i - self.n] + res[i]) % self.q
        return [x % self.q for x in res[:self.n]]

    def generate_keypair(self, *args, **kwargs):
        A = [[self._sample_noise_poly() for _ in range(self.l)] for _ in range(self.l)]
        s = [self._sample_noise_poly() for _ in range(self.l)]

        b = []
        for i in range(self.l):
            acc = [0] * self.n
            for j in range(self.l):
                acc = self._poly_add(acc, self._poly_mul(A[i][j], s[j]))
            b.append(acc)

        self._pubkey = (A, b)
        self._privkey = s
        self._generated = True
        print("Keypair generated.")

    def encripty(self, message: str) -> list:
        if not self._generated:
            raise RuntimeError("Key pair not generated")

        A, b = self._pubkey
        ciphertext = []

        bits = []
        for byte in message.encode('utf-8'):
            bits.extend([(byte >> i) & 1 for i in range(8)])

        for bit in bits:
            sp = [self._sample_noise_poly(self.eta) for _ in range(self.l)]

            bp = []
            for i in range(self.l):
                acc = [0] * self.n
                for j in range(self.l):
                    acc = self._poly_add(acc, self._poly_mul(A[j][i], sp[j]))
                bp.append(acc)

            vp = [0] * self.n
            for i in range(self.l):
                vp = self._poly_add(vp, self._poly_mul(b[i], sp[i]))

            vp[0] = (vp[0] + (bit * (self.q // self.p))) % self.q

            ciphertext.append((bp, vp))

        return ciphertext

    def decripty(self, ciphertext: list) -> str:
        if not self._generated:
            raise RuntimeError("Key pair not generated")

        s = self._privkey
        bits = []

        for bp, vp in ciphertext:
            v = [0] * self.n
            for i in range(self.l):
                v = self._poly_add(v, self._poly_mul(bp[i], s[i]))

            diff = (vp[0] - v[0]) % self.q
            bit = int((diff * self.p + self.q // 2) // self.q) % self.p
            bits.append(bit if bit < 2 else 0)

        bytes_out = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << j)
            bytes_out.append(byte)

        return bytes(bytes_out).decode('utf-8', errors='ignore')
            
    def export_keys(self):
        """
        Exporta as chaves pública e privada para arquivos de texto.
        """
        if not self._generated:
            raise RuntimeError("Key pair not generated")
            
        with open('saber_private_key.txt', 'w') as f1:
            f1.write(f"---------- Saber Private Key ----------\n\n")
            f1.write(f"s: {self._privkey}\n")
            
        with open('saber_public_key.txt', 'w') as f2:
            f2.write(f"---------- Saber Public Key ----------\n\n")
            f2.write(f"A: {self._pubkey[0]}\n")
            f2.write(f"b: {self._pubkey[1]}\n")
        
        print("Keys exported to 'saber_private_key.txt' and 'saber_public_key.txt'")

    @property
    def public_key(self):
        if not self._generated:
            raise RuntimeError("Key pair not generated")
        return (str(self._pubkey[0]) + str(self._pubkey[1])).encode('utf-8')

    @property
    def private_key(self):
        if not self._generated:
            raise RuntimeError("Key pair not generated")
        return (str(self._privkey)).encode('utf-8')

