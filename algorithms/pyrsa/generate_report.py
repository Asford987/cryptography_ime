import sys
import os
import time
import io
import psutil
import tracemalloc
from rsa import RSA

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
    # Nome do arquivo de relatório
    report_file = "rsa_keygen_report.txt"
    
    # Configurar captura de saída
    original_stdout = sys.stdout
    output = io.StringIO()
    sys.stdout = output
    
    try:
        print("\nRELATÓRIO DE DESEMPENHO - GERAÇÃO DE CHAVES RSA DE 2048 BITS")
        print(f"Data e hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Número de testes a serem executados
        num_testes = 5
        
        # Armazenar resultados para estatísticas
        tempos_geracao = []
        memoria_geracao = []
        tempos_primos = []
        tentativas_primos = []
        
        # Medir desempenho geral
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss / 1024  # KB
        tracemalloc.start()
        start_time = time.time()
        
        # Executar múltiplos testes para obter uma média confiável
        for i in range(num_testes):
            print(f"\n\nTESTE #{i+1} DE {num_testes}")
            print("-" * 50)
            
            # Criar uma nova instância RSA
            rsa_instance = RSA()
            
            # Medir tempo e memória específicos para a geração de chaves
            processo_memoria_inicial = process.memory_info().rss / 1024
            inicio_tempo = time.time()
            
            # Gerar par de chaves
            rsa_instance.generate_keypair(bits=2048)
            
            # Calcular tempo e memória finais
            fim_tempo = time.time()
            processo_memoria_final = process.memory_info().rss / 1024
            
            # Coletar dados para estatísticas
            tempo_geracao = fim_tempo - inicio_tempo
            memoria = processo_memoria_final - processo_memoria_inicial
            
            tempos_geracao.append(tempo_geracao)
            memoria_geracao.append(memoria)
            
            # Obter e imprimir chaves
            e, n = rsa_instance.public_key
            d, _ = rsa_instance.private_key
            
            # Formatar números grandes para melhor legibilidade
            def format_big_num(num):
                return str(num)[:50] + "..." if len(str(num)) > 50 else str(num)
            
            print(f"Chave pública (e): {format_big_num(e)}")
            print(f"Módulo (n): {format_big_num(n)}")
            
            # Exportar chaves somente no último teste
            if i == num_testes - 1:
                rsa_instance.export_keys()
                print("Chaves exportadas para arquivos.")
                
            # Exibir estatísticas específicas da geração de chaves
            print(f"\nEstatísticas do teste #{i+1}:")
            print(f"  Tempo total de geração do par de chaves: {tempo_geracao:.6f} segundos")
            print(f"  Memória utilizada: {memoria:.2f} KB")
            
            # Coletar dados sobre primos
            teste_primos_tentativas = []
            teste_primos_tempos = []
            
            for j, item in enumerate(rsa_instance.performance_stats['prime_gen']):
                print(f"  Primo {j+1}: {item['bits']} bits, {item['attempts']} tentativas, {item['time']:.6f} segundos")
                teste_primos_tentativas.append(item['attempts'])
                teste_primos_tempos.append(item['time'])
            
            tentativas_primos.append(teste_primos_tentativas)
            tempos_primos.append(teste_primos_tempos)
            
            # Imprimir estatísticas do Miller-Rabin
            total_chamadas = rsa_instance.performance_stats['miller_rabin']['total_calls']
            total_tempo = rsa_instance.performance_stats['miller_rabin']['total_time']
            
            print("\nTeste de Miller-Rabin (verificação de primalidade):")
            print(f"  Total de chamadas: {total_chamadas}")
            print(f"  Tempo total: {total_tempo:.6f} segundos")
            print(f"  Tempo médio por chamada: {total_tempo/max(1, total_chamadas):.8f} segundos")
            
            # Usar o método específico para estatísticas de geração de chaves
            rsa_instance.print_keygen_stats()
        
        # Finalizar medições globais
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_memory = process.memory_info().rss / 1024  # KB
        
        # Calcular estatísticas finais
        tempo_mediano = calculate_median(tempos_geracao)
        tempo_min = min(tempos_geracao)
        tempo_max = max(tempos_geracao)
        
        memoria_mediana = calculate_median(memoria_geracao)
        memoria_min = min(memoria_geracao)
        memoria_max = max(memoria_geracao)
        
        # Calcular medianas para tempos e tentativas de primos
        total_tentativas = []
        total_tempos_primos = []
        
        for lista in tentativas_primos:
            total_tentativas.extend(lista)
            
        for lista in tempos_primos:
            total_tempos_primos.extend(lista)
        
        primo_tentativas_mediana = calculate_median(total_tentativas)
        primo_tentativas_min = min(total_tentativas)
        primo_tentativas_max = max(total_tentativas)
        
        primo_tempo_mediano = calculate_median(total_tempos_primos)
        primo_tempo_min = min(total_tempos_primos)
        primo_tempo_max = max(total_tempos_primos)
        
        # Exibir resumo estatístico
        print(f"\n{'='*50}")
        print(f"RESUMO ESTATÍSTICO DA GERAÇÃO DE CHAVES ({num_testes} testes):")
        
        print(f"\nPar de chaves RSA (2048 bits):")
        print(f"  Tempo mediano de geração: {tempo_mediano:.6f} segundos")
        print(f"  Tempo mínimo: {tempo_min:.6f} segundos")
        print(f"  Tempo máximo: {tempo_max:.6f} segundos")
        print(f"  Memória mediana utilizada: {memoria_mediana:.2f} KB")
        
        print(f"\nGeração de números primos:")
        print(f"  Tempo mediano por primo: {primo_tempo_mediano:.6f} segundos")
        print(f"  Tempo mínimo: {primo_tempo_min:.6f} segundos")
        print(f"  Tempo máximo: {primo_tempo_max:.6f} segundos")
        print(f"  Mediana de tentativas por primo: {primo_tentativas_mediana:.1f}")
        print(f"  Mínimo de tentativas: {primo_tentativas_min}")
        print(f"  Máximo de tentativas: {primo_tentativas_max}")
        
        print(f"\n{'='*50}")
        print(f"PERFORMANCE TOTAL DOS TESTES:")
        print(f"Tempo total: {end_time - start_time:.6f} segundos")
        print(f"Memória inicial do processo: {start_memory:.2f} KB")
        print(f"Memória final do processo: {end_memory:.2f} KB")
        print(f"Diferença de memória: {end_memory - start_memory:.2f} KB")
        print(f"Pico de uso de memória: {peak / 1024:.2f} KB")
        print(f"{'='*50}")
        
        # Voltar stdout para o original para informar ao usuário
        sys.stdout = original_stdout
        print(f"Gerando relatório em: {os.path.abspath(report_file)}")
        
        # Salvar o relatório em arquivo com codificação UTF-8
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