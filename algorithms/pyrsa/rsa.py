import random


class RSA:
    def __init__(self):
        self._generated = False
        self._pubkey = None
        self._privkey = None


    @property
    def public_key(self):
        if not self._generated: raise RuntimeError("Key pair not generated")
        return self._pubkey


    @property
    def private_key(self):
        if not self._generated: raise RuntimeError("Key pair not generated") 
        return self._privkey


    def _is_prime(self, n, precision=40):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        
        small_primes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
        for p in small_primes:
            if n == p:
                return True
            if n % p == 0:
                return False
        
        return self._miller_rabin_test(n, k=precision)
            
    
    def _generate_prime(self, bits, precision=40):
        print(f"Generating prime of {bits} bits...")
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            
            if self._is_prime(n, precision):
                print(f"Prime generated: {n}")
                return n


    def generate_keypair(self, bits=1024):
        p = self._generate_prime(bits // 2)
        q = self._generate_prime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        while True:
            try:
                d = self._get_mod_inverse(e, phi)
                break
            except:
                e += 2
                continue

        self._generated = True
        self._pubkey = (e, n)
        self._privkey = (d, n)

    def encripty(self, msg:str)->str:
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        print(f"Encrypting message: {msg}")
        parsed_msg:int = self._text_to_int(msg)
        encripted_msg = pow(parsed_msg, self._pubkey[0], self._pubkey[1])
        return encripted_msg

    def decripty(self, encripted_msg:int)->str:
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        decripted_msg:int = pow(encripted_msg, self._privkey[0], self._privkey[1])
        text:str = self._int_to_text(decripted_msg)
        return text

    def _get_mod_inverse(self, inverse:int, modulo:int)->int:
        x = [1,0]
        y = [0,1]
        r = [modulo, inverse]
        
        while(r[1] != 1):
            q = r[0]//r[1]
            resto = r[0] % r[1]
            if (resto == 0):
                break
            
            x_atual = x[0] - q*x[1]
            y_atual = y[0] - q*y[1]
            
            r[0] = r[1]
            r[1] = resto
            
            x[0] = x[1]
            x[1] = x_atual
            
            y[0] = y[1]
            y[1] = y_atual
        
        if(r[1] == 1):
            return y[1] % modulo
        
        else:
            raise Exception(f"mdc({inverse}, {modulo}) = {r[1]} != 1")


    def _text_to_int(self, message):
        result = 0
        for char in message:
            result = result * 256 + ord(char)
        return result

    def _int_to_text(self, number):
        text = ""
        while number > 0:
            text = chr(number % 256) + text
            number //= 256
        return text
    
    def _miller_rabin_test(self, n, k=40):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True


if __name__ == "__main__":
    rsa = RSA()
    mensagem = "Bom dia, Espírito Santo!"
    print(mensagem)

    rsa.generate_keypair()
    print(f"public key: {rsa.public_key}")
    print(f"private key: {rsa.private_key}")
    encripted_msg = rsa.encripty(mensagem)
    
    decripted_msg = rsa.decripty(encripted_msg)
    print(f"Printing decrypted message: {decripted_msg}")