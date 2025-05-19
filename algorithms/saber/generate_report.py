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
    Executa apenas a geração de chaves RSA de 2048 bits e salva o relatório de desempenho,
    focando apenas nos métodos _generate_prime e generate_keypair
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
        
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss / 1024  # KB
        tracemalloc.start()
        start_time = time.time()
        
        for i in range(num_testes):
            print(f"\n\nTESTE #{i+1} DE {num_testes}")
            print("-" * 50)
            
            saber_instance = Saber()
            
            processo_memoria_inicial = process.memory_info().rss / 1024
            inicio_tempo = time.time()
            
            saber_instance.generate_keypair()
            
            fim_tempo = time.time()
            processo_memoria_final = process.memory_info().rss / 1024
            
            tempo_geracao = fim_tempo - inicio_tempo
            memoria = processo_memoria_final - processo_memoria_inicial
            
            tempos_geracao.append(tempo_geracao)
            memoria_geracao.append(memoria)
            
            # Obter e imprimir chaves !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            A = saber_instance.public_key
            s = saber_instance.private_key
            
            def format_big_num(num):
                return str(num)[:50] + "..." if len(str(num)) > 50 else str(num)
            
            print(f"Chave pública (e): {format_big_num(A)}")
            
            if i == num_testes - 1:
                # saber_instance.export_keys()
                print("Chaves exportadas para arquivos.")
                
            print(f"\nEstatísticas do teste #{i+1}:")
            print(f"  Tempo total de geração do par de chaves: {tempo_geracao:.6f} segundos")
            print(f"  Memória utilizada: {memoria:.2f} KB")
            
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_memory = process.memory_info().rss / 1024  # KB
        
        tempo_mediano = calculate_median(tempos_geracao)
        tempo_min = min(tempos_geracao)
        tempo_max = max(tempos_geracao)
        
        memoria_mediana = calculate_median(memoria_geracao)
        
        print(f"\n{'='*50}")
        print(f"RESUMO ESTATÍSTICO DA GERAÇÃO DE CHAVES ({num_testes} testes):")
        
        print(f"\nPar de chaves SABER:")
        print(f"  Tempo mediano de geração: {tempo_mediano:.6f} segundos")
        print(f"  Tempo mínimo: {tempo_min:.6f} segundos")
        print(f"  Tempo máximo: {tempo_max:.6f} segundos")
        print(f"  Memória mediana utilizada: {memoria_mediana:.2f} KB")
        
        print(f"\n{'='*50}")
        print(f"PERFORMANCE TOTAL DOS TESTES:")
        print(f"Tempo total: {end_time - start_time:.6f} segundos")
        print(f"Memória inicial do processo: {start_memory:.2f} KB")
        print(f"Memória final do processo: {end_memory:.2f} KB")
        print(f"Diferença de memória: {end_memory - start_memory:.2f} KB")
        print(f"Pico de uso de memória: {peak / 1024:.2f} KB")
        print(f"{'='*50}")
        
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
        # Restaurar stdout
        sys.stdout = original_stdout

if __name__ == "__main__":
    main() 