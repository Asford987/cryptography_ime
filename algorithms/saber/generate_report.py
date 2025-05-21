import sys
import os
import time
import io
import psutil
import tracemalloc
from saber import Saber


def calculate_median(numbers):
    """
    Calcula a mediana de uma lista de números.
    """
    sorted_numbers = sorted(numbers)
    n = len(sorted_numbers)
    if n == 0:
        return 0
    if n % 2 == 0:
        return (sorted_numbers[n//2 - 1] + sorted_numbers[n//2]) / 2
    return sorted_numbers[n//2]

def main():
    """
    Executa a geração de chaves Saber e salva o relatório de desempenho,
    focando nos métodos de geração de chaves e operações internas do algoritmo.
    """
    report_file = "saber_keygen_report.txt"
    
    original_stdout = sys.stdout
    output = io.StringIO()
    sys.stdout = output
    
    try:
        print("\nRELATÓRIO DE DESEMPENHO - GERAÇÃO DE CHAVES SABER")
        print(f"Data e hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        num_testes = 5
        
        tempos_geracao = []
        memoria_geracao = []
        tempos_poly_add = []
        tempos_poly_mul = []
        tempos_sample_noise_poly = []
        tempos_round = []
        tempos_recover = []
        tempos_encode = []
        tempos_decode = []
        contagem_poly_add = []
        contagem_poly_mul = []
        contagem_sample_noise_poly = []
        contagem_round = []
        contagem_recover = []
        contagem_encode = []
        contagem_decode = []
        
        original_poly_add = Saber._poly_add
        original_poly_mul = Saber._poly_mul
        original_sample_noise_poly = Saber._sample_noise_poly
        original_encode_message = Saber._encode_message
        original_decode_message = Saber._decode_message
        original_round_message = Saber._round_message
        original_recover_message = Saber._recover_message
        
        def instrumentar_poly_add(self, a, b):
            inicio = time.time()
            resultado = original_poly_add(self, a, b)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['poly_add'].append(tempo)
            return resultado
        
        def instrumentar_poly_mul(self, a, b):
            inicio = time.time()
            resultado = original_poly_mul(self, a, b)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['poly_mul'].append(tempo)
            return resultado
        
        def instrumentar_sample_noise_poly(self):
            inicio = time.time()
            resultado = original_sample_noise_poly(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        def instrumentar_recover_message(self):
            inicio = time.time()
            resultado = original_recover_message(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        def instrumentar_encode_message(self):
            inicio = time.time()
            resultado = original_encode_message(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        def instrumentar_round_message(self):
            inicio = time.time()
            resultado = original_round_message(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        def instrumentar_decode_message(self):
            inicio = time.time()
            resultado = original_decode_message(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        Saber._poly_add = instrumentar_poly_add
        Saber._poly_mul = instrumentar_poly_mul
        Saber._sample_noise_poly = instrumentar_sample_noise_poly
        
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss / 1024  # KB
        tracemalloc.start()
        start_time = time.time()
        
        for i in range(num_testes):
            print(f"\n\nTESTE #{i+1} DE {num_testes}")
            print("-" * 50)
            
            saber_instance = Saber()
            saber_instance._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            
            processo_memoria_inicial = process.memory_info().rss / 1024
            inicio_tempo = time.time()
            
            saber_instance.generate_keypair()
            
            fim_tempo = time.time()
            processo_memoria_final = process.memory_info().rss / 1024
            
            tempo_geracao = fim_tempo - inicio_tempo
            memoria = processo_memoria_final - processo_memoria_inicial
            
            tempos_geracao.append(tempo_geracao)
            memoria_geracao.append(memoria)
            
            contagem_poly_add.append(len(saber_instance._stats['poly_add']))
            contagem_poly_mul.append(len(saber_instance._stats['poly_mul']))
            contagem_sample_noise_poly.append(len(saber_instance._stats['random_poly']))
            
            tempos_poly_add.extend(saber_instance._stats['poly_add'])
            tempos_poly_mul.extend(saber_instance._stats['poly_mul'])
            tempos_sample_noise_poly.extend(saber_instance._stats['random_poly'])
            
            try:
                pubkey = saber_instance.public_key
                privkey = saber_instance.private_key
                
                print(f"Chave pública: {pubkey}")
                print(f"Chave privada: {privkey}")
            except Exception as e:
                print(f"Erro ao exibir chaves: {str(e)}")
                
            if i == num_testes - 1:
                saber_instance.export_keys()
                print("Chaves exportadas para arquivos.")
                
            print(f"\nEstatísticas do teste #{i+1}:")
            print(f"  Tempo total de geração do par de chaves: {tempo_geracao:.6f} segundos")
            print(f"  Memória utilizada: {memoria:.2f} KB")
            
            print("\nOperações internas:")
            print(f"  Poly Add: {len(saber_instance._stats['poly_add'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['poly_add']):.6f} segundos")
            print(f"  Poly Mul: {len(saber_instance._stats['poly_mul'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['poly_mul']):.6f} segundos")
            print(f"  Random Poly: {len(saber_instance._stats['random_poly'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['random_poly']):.6f} segundos")
        
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_memory = process.memory_info().rss / 1024  # KB
        
        tempo_mediano = calculate_median(tempos_geracao)
        tempo_min = min(tempos_geracao)
        tempo_max = max(tempos_geracao)
        
        memoria_mediana = calculate_median(memoria_geracao)
        memoria_min = min(memoria_geracao)
        memoria_max = max(memoria_geracao)
        
        poly_add_tempo_mediano = calculate_median(tempos_poly_add) if tempos_poly_add else 0
        poly_mul_tempo_mediano = calculate_median(tempos_poly_mul) if tempos_poly_mul else 0
        random_poly_tempo_mediano = calculate_median(tempos_sample_noise_poly) if tempos_sample_noise_poly else 0
        
        poly_add_chamadas_mediana = calculate_median(contagem_poly_add) if contagem_poly_add else 0
        poly_mul_chamadas_mediana = calculate_median(contagem_poly_mul) if contagem_poly_mul else 0
        random_poly_chamadas_mediana = calculate_median(contagem_sample_noise_poly) if contagem_sample_noise_poly else 0
        
        print(f"\n{'='*50}")
        print(f"RESUMO ESTATÍSTICO DA GERAÇÃO DE CHAVES ({num_testes} testes):")
        
        print(f"\nPar de chaves SABER:")
        print(f"  Tempo mediano de geração: {tempo_mediano:.6f} segundos")
        print(f"  Tempo mínimo: {tempo_min:.6f} segundos")
        print(f"  Tempo máximo: {tempo_max:.6f} segundos")
        print(f"  Memória mediana utilizada: {memoria_mediana:.2f} KB")
        print(f"  Memória mínima: {memoria_min:.2f} KB")
        print(f"  Memória máxima: {memoria_max:.2f} KB")
        
        print(f"\nOperações básicas do algoritmo:")
        print(f"  Poly Add: mediana de {poly_add_chamadas_mediana:.1f} chamadas por geração")
        print(f"    Tempo mediano por operação: {poly_add_tempo_mediano:.8f} segundos")
        print(f"  Poly Mul: mediana de {poly_mul_chamadas_mediana:.1f} chamadas por geração")
        print(f"    Tempo mediano por operação: {poly_mul_tempo_mediano:.8f} segundos")
        print(f"  Random Poly: mediana de {random_poly_chamadas_mediana:.1f} chamadas por geração")
        print(f"    Tempo mediano por operação: {random_poly_tempo_mediano:.8f} segundos")
        
        print(f"\n{'='*50}")
        print(f"PERFORMANCE TOTAL DOS TESTES:")
        print(f"Tempo total: {end_time - start_time:.6f} segundos")
        print(f"Memória inicial do processo: {start_memory:.2f} KB")
        print(f"Memória final do processo: {end_memory:.2f} KB")
        print(f"Diferença de memória: {end_memory - start_memory:.2f} KB")
        print(f"Pico de uso de memória: {peak / 1024:.2f} KB")
        print(f"{'='*50}")
        
        Saber._poly_add = original_poly_add
        Saber._poly_mul = original_poly_mul
        Saber._sample_noise_poly = original_sample_noise_poly
        
        sys.stdout = original_stdout
        print(f"Gerando relatório em: {os.path.abspath(report_file)}")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(output.getvalue())
            
        print(f"Relatório gerado com sucesso!")
        
    except Exception as e:
        sys.stdout = original_stdout
        print(f"Erro: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        sys.stdout = original_stdout
        
        if 'original_poly_add' in locals():
            Saber._poly_add = original_poly_add
        if 'original_poly_mul' in locals():
            Saber._poly_mul = original_poly_mul
        if 'original_sample_noise_poly' in locals():
            Saber._sample_noise_poly = original_sample_noise_poly

if __name__ == "__main__":
    main() 