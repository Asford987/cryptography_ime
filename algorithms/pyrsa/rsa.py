import random
import time
import tracemalloc
import psutil
import os
from functools import wraps

def measure_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss / 1024  # KB
        tracemalloc.start()
        
        start_time = time.time()
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_memory = process.memory_info().rss / 1024  # KB
        
        print(f"\n{'='*50}")
        print(f"Performance de {func.__name__}:")
        print(f"Tempo de execução: {execution_time:.6f} segundos")
        print(f"Memória inicial: {start_memory:.2f} KB")
        print(f"Memória final: {end_memory:.2f} KB")
        print(f"Diferença de memória: {end_memory - start_memory:.2f} KB")
        print(f"Pico de uso de memória (tracemalloc): {peak / 1024:.2f} KB")
        print(f"{'='*50}")
        
        return result
    return wrapper


class RSA:
    def __init__(self):
        self._generated = False
        self._pubkey = None
        self._privkey = None
        self.performance_stats = {
            'prime_gen': [],
            'miller_rabin': {'total_calls': 0, 'total_time': 0}
        }


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
            
    
    @measure_performance
    def _generate_prime(self, bits, precision=40):
        
        start_time = time.time()
        num_attempts = 0
        
        while True:
            num_attempts += 1
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            
            if self._is_prime(n, precision):
                end_time = time.time()
                gen_time = end_time - start_time
                
                self.performance_stats['prime_gen'].append({
                    'bits': bits,
                    'attempts': num_attempts,
                    'time': gen_time,
                })
                
                print(f"Prime generated: {n}")
                print(f"Generated in {gen_time:.6f} seconds after {num_attempts} attempts.")
                return n


    @measure_performance
    def generate_keypair(self, bits=1024):
        p = self._generate_prime(bits // 2)
        q = self._generate_prime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        
        start_time = time.time()
        while True:
            try:
                d = self._get_inverse_mod(e, phi)
                break
            except:
                e += 2
                continue
        inverse_time = time.time() - start_time
        print(f"Inverso multiplicativo calculado em {inverse_time:.6f} segundos.")

        self._generated = True
        self._pubkey = (e, n)
        self._privkey = (d, n)


    @measure_performance
    def encripty(self, msg:str)->str:
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        print(f"Encrypting message: {msg}")
        parsed_msg:int = self._text_to_int(msg)
        encripted_msg = pow(parsed_msg, self._pubkey[0], self._pubkey[1])
        return encripted_msg


    @measure_performance
    def decripty(self, encripted_msg:int)->str:
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        decripted_msg:int = pow(encripted_msg, self._privkey[0], self._privkey[1])
        text:str = self._int_to_text(decripted_msg)
        return text


    @measure_performance 
    def _get_inverse_mod(self, inverse:int, modulo:int)->int:
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
        self.performance_stats['miller_rabin']['total_calls'] += 1
        
        start_time = time.time()
        
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
        
        result = True
        
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
                result = False
                break
        
        end_time = time.time()
        self.performance_stats['miller_rabin']['total_time'] += (end_time - start_time)
        
        return result
    
    
    def export_keys(self):
        with open('rsa_private_key.txt', 'w') as f1:
            f1.write(f"---------- RSA Private Key ----------\n\n")
            f1.write(f"d: {self._privkey[0]}\n")
            f1.write(f"n: {self._privkey[1]}\n")

        with open('rsa_public_key.txt', 'w') as f2:
            f2.write(f"---------- RSA Public Key ----------\n\n")
            f2.write(f"e: {self._pubkey[0]}\n")
            f2.write(f"n: {self._pubkey[1]}\n")
    
    
    def print_performance_stats(self):
        print("\n" + "="*50)
        print("ESTATÍSTICAS DETALHADAS:")
        
        print("\nGeração de números primos:")
        total_time = sum(item['time'] for item in self.performance_stats['prime_gen'])
        total_attempts = sum(item['attempts'] for item in self.performance_stats['prime_gen'])
        
        for i, item in enumerate(self.performance_stats['prime_gen']):
            print(f"  Primo {i+1}: {item['bits']} bits, {item['attempts']} tentativas, {item['time']:.6f} segundos")
        
        print(f"\nTotal de números primos gerados: {len(self.performance_stats['prime_gen'])}")
        print(f"Tempo total de geração de primos: {total_time:.6f} segundos")
        print(f"Média de tentativas por primo: {total_attempts/len(self.performance_stats['prime_gen']):.1f}")
        
        print("\nTeste de Miller-Rabin:")
        print(f"  Total de chamadas: {self.performance_stats['miller_rabin']['total_calls']}")
        print(f"  Tempo total: {self.performance_stats['miller_rabin']['total_time']:.6f} segundos")
        print(f"  Tempo médio por chamada: {self.performance_stats['miller_rabin']['total_time']/max(1,self.performance_stats['miller_rabin']['total_calls']):.6f} segundos")
        
        print("="*50)


if __name__ == "__main__":
    def format_big_num(num):
        return str(num)[:50] + "..." if len(str(num)) > 50 else str(num)
    
    rsa = RSA()
    mensagem = "Bom dia, Espírito Santo!"

    print("\nIniciando teste de performance do RSA\n")
    
    process = psutil.Process(os.getpid())
    start_memory = process.memory_info().rss / 1024  # KB
    
    tracemalloc.start()
    start_time = time.time()
    
    rsa.generate_keypair()
    rsa.export_keys()
    
    e, n = rsa.public_key
    d, _ = rsa.private_key
    print(f"public key: (e={format_big_num(e)}, n={format_big_num(n)})")
    print(f"private key: (d={format_big_num(d)}, n={format_big_num(n)})")
    
    encripted_msg = rsa.encripty(mensagem)
    decripted_msg = rsa.decripty(encripted_msg)
    print(f"Mensagem decriptada: {decripted_msg}")
    
    end_time = time.time()
    total_time = end_time - start_time
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    end_memory = process.memory_info().rss / 1024  # KB
    
    print(f"\n{'='*50}")
    print(f"PERFORMANCE TOTAL:")
    print(f"Tempo total de execução: {total_time:.6f} segundos")
    print(f"Memória inicial do processo: {start_memory:.2f} KB")
    print(f"Memória final do processo: {end_memory:.2f} KB")
    print(f"Diferença de memória: {end_memory - start_memory:.2f} KB")
    print(f"Pico de uso de memória (tracemalloc): {peak / 1024:.2f} KB")
    print(f"{'='*50}")
    
    rsa.print_performance_stats()