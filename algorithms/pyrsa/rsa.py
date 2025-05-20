import random
import time
import tracemalloc
import psutil
import os
from functools import wraps
import codecs

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
    def generate_keypair(self, bits=3072):
        """
        Gera um par de chaves RSA.
        Para mensagens grandes, é recomendado usar bits >= 2048.
        
        Args:
            bits: Tamanho da chave em bits. Padrão: 2048.
        """
        # Para textos longos, verificamos se o tamanho da chave é suficiente
        if bits < 2048:
            print("AVISO: Para textos longos ou com muitos caracteres especiais,")
            print("       é recomendado usar chaves de pelo menos 2048 bits.")
            
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
        
        # Verificar e exibir o tamanho máximo da mensagem em bytes
        max_bytes = (bits // 8) - 11  # Usando uma margem de segurança
        print(f"Tamanho máximo da mensagem: aproximadamente {max_bytes} bytes")
        print(f"Isso equivale a cerca de {max_bytes // 4} caracteres UTF-8 típicos")


    def encripty(self, msg:str)->list:
        """
        Criptografa uma mensagem usando a chave pública.
        Para mensagens longas, divide em blocos compatíveis com o tamanho da chave.
        
        Args:
            msg: A mensagem a ser criptografada
            
        Returns:
            Uma lista de inteiros representando os blocos criptografados
        """
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        print(f"Criptografando mensagem de {len(msg)} caracteres ({len(msg.encode('utf-8'))} bytes)")
        
        # Calcular o tamanho máximo de cada bloco em bytes
        # n é o módulo RSA, cujo tamanho em bytes determina o limite máximo
        key_size_bytes = (self._pubkey[1].bit_length() + 7) // 8
        max_block_size = key_size_bytes - 11  # Margem de segurança
        
        # Converter a mensagem em bytes
        message_bytes = msg.encode('utf-8')
        total_bytes = len(message_bytes)
        
        # Dividir em blocos se necessário
        encrypted_blocks = []
        
        if total_bytes <= max_block_size:
            # Mensagem pequena, não precisa dividir
            parsed_msg = self._text_to_int(msg)
            encrypted_blocks.append(pow(parsed_msg, self._pubkey[0], self._pubkey[1]))
            print(f"Mensagem criptografada em um único bloco")
        else:
            # Mensagem grande, dividir em blocos
            num_blocks = (total_bytes + max_block_size - 1) // max_block_size  # Arredondamento para cima
            print(f"Dividindo mensagem em {num_blocks} blocos")
            
            for i in range(0, total_bytes, max_block_size):
                # Obter o bloco atual
                block = message_bytes[i:i + max_block_size]
                
                # Converter para inteiro
                block_int = 0
                for byte in block:
                    block_int = (block_int << 8) | byte
                
                # Criptografar o bloco
                encrypted_block = pow(block_int, self._pubkey[0], self._pubkey[1])
                encrypted_blocks.append(encrypted_block)
                
            print(f"Criptografia concluída: {len(encrypted_blocks)} blocos gerados")
        
        return encrypted_blocks


    def decripty(self, encrypted_data)->str:
        """
        Descriptografa dados usando a chave privada.
        Suporta tanto um único valor inteiro quanto uma lista de blocos criptografados.
        
        Args:
            encrypted_data: Um inteiro ou lista de inteiros representando dados criptografados
            
        Returns:
            A mensagem descriptografada
        """
        if not self._generated: raise RuntimeError("Key pair not generated")
        
        # Verificar se é um bloco único ou múltiplos blocos
        if isinstance(encrypted_data, int):
            # Bloco único
            decrypted_int = pow(encrypted_data, self._privkey[0], self._privkey[1])
            text = self._int_to_text(decrypted_int)
            print(f"Mensagem descriptografada em um único bloco")
            return text
        elif isinstance(encrypted_data, list):
            # Múltiplos blocos
            print(f"Descriptografando {len(encrypted_data)} blocos")
            result_parts = []
            
            for i, block in enumerate(encrypted_data):
                # Descriptografar cada bloco
                decrypted_int = pow(block, self._privkey[0], self._privkey[1])
                
                # Converter para bytes
                bytes_array = []
                while decrypted_int > 0:
                    bytes_array.append(decrypted_int & 0xFF)
                    decrypted_int >>= 8
                
                bytes_array.reverse()
                
                # Adicionar à lista de partes
                try:
                    part = bytes(bytes_array).decode('utf-8', errors='replace')
                    result_parts.append(part)
                except Exception as e:
                    print(f"Erro ao decodificar bloco {i}: {e}")
                    result_parts.append("?")
            
            # Juntar todas as partes
            return "".join(result_parts)
        else:
            raise ValueError("Formato de dados criptografados inválido")


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
        """
        Converte texto para inteiro usando codificação UTF-8
        para suportar adequadamente caracteres acentuados
        """
        # Codificar a mensagem em bytes usando UTF-8
        message_bytes = message.encode('utf-8')
        
        # Converter bytes para um número inteiro
        result = 0
        for byte in message_bytes:
            result = (result << 8) | byte
            
        return result


    def _int_to_text(self, number):
        """
        Converte um inteiro de volta para texto usando UTF-8
        """
        # Converter número para bytes
        bytes_array = []
        while number > 0:
            bytes_array.append(number & 0xFF)
            number >>= 8
            
        # Reverter a ordem dos bytes
        bytes_array.reverse()
        
        # Converter bytes para texto usando UTF-8
        try:
            # Converter lista de bytes para bytes object
            byte_data = bytes(bytes_array)
            
            # Verificar se os bytes são válidos antes de decodificar
            if not byte_data:
                return ""
                
            # Decodificar bytes para texto com tratamento de erro
            return byte_data.decode('utf-8', errors='replace')
            
        except Exception as e:
            print(f"Erro ao decodificar: {e}")
            print(f"Bytes: {bytes_array[:20]}{'...' if len(bytes_array) > 20 else ''}")
            
            # Tentar recuperar ao menos parte do texto
            try:
                # Tentar decodificar ignorando caracteres problemáticos
                return bytes(bytes_array).decode('utf-8', errors='ignore')
            except:
                # Em último caso, fazer uma representação básica
                return "".join([chr(b) if 32 <= b < 127 else '?' for b in bytes_array])
    
    
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
    
    
    def print_keygen_stats(self):
        """
        Imprime estatísticas detalhadas sobre o processo de geração de chaves,
        focando apenas nos métodos _generate_prime e generate_keypair
        """
        print("\n" + "="*50)
        print("ESTATÍSTICAS DE GERAÇÃO DE CHAVES:")
        
        print("\nGeração de números primos:")
        total_time = sum(item['time'] for item in self.performance_stats['prime_gen'])
        total_attempts = sum(item['attempts'] for item in self.performance_stats['prime_gen'])
        
        for i, item in enumerate(self.performance_stats['prime_gen']):
            print(f"  Primo {i+1}: {item['bits']} bits, {item['attempts']} tentativas, {item['time']:.6f} segundos")
        
        print(f"\nTotal de números primos gerados: {len(self.performance_stats['prime_gen'])}")
        print(f"Tempo total de geração de primos: {total_time:.6f} segundos")
        print(f"Média de tentativas por primo: {total_attempts/len(self.performance_stats['prime_gen']):.1f}")
        
        print("\nTeste de Miller-Rabin (usado na verificação de primalidade):")
        print(f"  Total de chamadas: {self.performance_stats['miller_rabin']['total_calls']}")
        print(f"  Tempo total: {self.performance_stats['miller_rabin']['total_time']:.6f} segundos")
        print(f"  Tempo médio por chamada: {self.performance_stats['miller_rabin']['total_time']/max(1,self.performance_stats['miller_rabin']['total_calls']):.6f} segundos")
        
        print("="*50)
