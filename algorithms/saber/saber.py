import random


class Saber:
    def __init__(self):
        self.q = 8192
        self.p = 1024
        self.n = 4
        self.l = 2

        self._generated = False
        self._pubkey = None
        self._privkey = None

    def _random_poly(self):
        return [random.randint(0, self.q - 1) for _ in range(self.n)]

    def _poly_add(self, a, b):
        return [(x + y) % self.q for x, y in zip(a, b)]

    def _poly_mul(self, a, b):
        res = [0] * (2 * self.n - 1)
        for i in range(self.n):
            for j in range(self.n):
                res[i + j] += a[i] * b[j]
        for i in range(self.n, 2 * self.n - 1):
            res[i - self.n] = (res[i - self.n] + res[i]) % self.q
        return [x % self.q for x in res[:self.n]]

    def generate_keypair(self):
        A = [[self._random_poly() for _ in range(self.l)] for _ in range(self.l)]
        s = [self._random_poly() for _ in range(self.l)]

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

    def encripty(self, message: str) -> tuple:
        if not self._generated:
            raise RuntimeError("Key pair not generated")

        m = ord(message[0]) % self.p

        A, b = self._pubkey
        sp = [self._random_poly() for _ in range(self.l)]

        bp = []
        for i in range(self.l):
            acc = [0] * self.n
            for j in range(self.l):
                acc = self._poly_add(acc, self._poly_mul(A[j][i], sp[j]))
            bp.append(acc)

        vp = [0] * self.n
        for i in range(self.l):
            vp = self._poly_add(vp, self._poly_mul(b[i], sp[i]))

        vp[0] = (vp[0] + (m * (self.q // self.p))) % self.q

        return (bp, vp)

    def decripty(self, ciphertext: tuple) -> str:
        if not self._generated:
            raise RuntimeError("Key pair not generated")

        bp, vp = ciphertext
        s = self._privkey

        v = [0] * self.n
        for i in range(self.l):
            v = self._poly_add(v, self._poly_mul(bp[i], s[i]))

        diff = (vp[0] - v[0]) % self.q
        m = int((diff * self.p) / self.q) % self.p
        return chr(m)

    @property
    def public_key(self):
        if not self._generated:
            raise RuntimeError("Key pair not generated")
        return self._pubkey

    @property
    def private_key(self):
        if not self._generated:
            raise RuntimeError("Key pair not generated")
        return self._privkey


if __name__ == "__main__":
    saber = Saber()
    msg = "H"
    print(f"Original: {msg}")

    saber.generate_keypair()
    ct = saber.encripty(msg)
    dec = saber.decripty(ct)

    print(f"Decrypted: {dec}")
