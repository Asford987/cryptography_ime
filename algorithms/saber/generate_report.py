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
    # Nome do arquivo de relatório
    report_file = "saber_keygen_report.txt"
    
    # Configurar captura de saída
    original_stdout = sys.stdout
    output = io.StringIO()
    sys.stdout = output
    
    try:
        print("\nRELATÓRIO DE DESEMPENHO - GERAÇÃO DE CHAVES SABER")
        print(f"Data e hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Número de testes a serem executados
        num_testes = 5
        
        # Armazenar resultados para estatísticas
        tempos_geracao = []
        memoria_geracao = []
        tempos_poly_add = []
        tempos_poly_mul = []
        tempos_random_poly = []
        contagem_poly_add = []
        contagem_poly_mul = []
        contagem_random_poly = []
        
        # Monitorar as funções internas do Saber
        original_poly_add = Saber._poly_add
        original_poly_mul = Saber._poly_mul
        original_random_poly = Saber._random_poly
        
        # Substituir as funções por versões instrumentadas
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
        
        def instrumentar_random_poly(self):
            inicio = time.time()
            resultado = original_random_poly(self)
            tempo = time.time() - inicio
            if not hasattr(self, '_stats'):
                self._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            self._stats['random_poly'].append(tempo)
            return resultado
        
        # Aplicar as funções instrumentadas
        Saber._poly_add = instrumentar_poly_add
        Saber._poly_mul = instrumentar_poly_mul
        Saber._random_poly = instrumentar_random_poly
        
        # Medir desempenho geral
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss / 1024  # KB
        tracemalloc.start()
        start_time = time.time()
        
        # Executar múltiplos testes para obter uma mediana confiável
        for i in range(num_testes):
            print(f"\n\nTESTE #{i+1} DE {num_testes}")
            print("-" * 50)
            
            # Criar uma nova instância Saber
            saber_instance = Saber()
            saber_instance._stats = {'poly_add': [], 'poly_mul': [], 'random_poly': []}
            
            # Medir tempo e memória específicos para a geração de chaves
            processo_memoria_inicial = process.memory_info().rss / 1024
            inicio_tempo = time.time()
            
            # Gerar par de chaves
            saber_instance.generate_keypair()
            
            # Calcular tempo e memória finais
            fim_tempo = time.time()
            processo_memoria_final = process.memory_info().rss / 1024
            
            # Coletar dados para estatísticas
            tempo_geracao = fim_tempo - inicio_tempo
            memoria = processo_memoria_final - processo_memoria_inicial
            
            tempos_geracao.append(tempo_geracao)
            memoria_geracao.append(memoria)
            
            # Obter estatísticas das operações internas
            contagem_poly_add.append(len(saber_instance._stats['poly_add']))
            contagem_poly_mul.append(len(saber_instance._stats['poly_mul']))
            contagem_random_poly.append(len(saber_instance._stats['random_poly']))
            
            tempos_poly_add.extend(saber_instance._stats['poly_add'])
            tempos_poly_mul.extend(saber_instance._stats['poly_mul'])
            tempos_random_poly.extend(saber_instance._stats['random_poly'])
            
            # Obter e imprimir chaves
            try:
                pubkey = saber_instance.public_key
                privkey = saber_instance.private_key
                
                # Formatar números grandes para melhor legibilidade
                def format_big_num(num):
                    return str(num)[:50] + "..." if len(str(num)) > 50 else str(num)
                
                print(f"Chave pública: {format_big_num(pubkey)}")
                print(f"Chave privada: {format_big_num(privkey)}")
            except Exception as e:
                print(f"Erro ao exibir chaves: {str(e)}")
                
            # Exibir estatísticas específicas da geração de chaves
            print(f"\nEstatísticas do teste #{i+1}:")
            print(f"  Tempo total de geração do par de chaves: {tempo_geracao:.6f} segundos")
            print(f"  Memória utilizada: {memoria:.2f} KB")
            
            # Exibir estatísticas das operações internas
            print("\nOperações internas:")
            print(f"  Poly Add: {len(saber_instance._stats['poly_add'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['poly_add']):.6f} segundos")
            print(f"  Poly Mul: {len(saber_instance._stats['poly_mul'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['poly_mul']):.6f} segundos")
            print(f"  Random Poly: {len(saber_instance._stats['random_poly'])} chamadas, "
                f"tempo total: {sum(saber_instance._stats['random_poly']):.6f} segundos")
        
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
        
        # Calcular medianas para operações internas
        poly_add_tempo_mediano = calculate_median(tempos_poly_add) if tempos_poly_add else 0
        poly_mul_tempo_mediano = calculate_median(tempos_poly_mul) if tempos_poly_mul else 0
        random_poly_tempo_mediano = calculate_median(tempos_random_poly) if tempos_random_poly else 0
        
        poly_add_chamadas_mediana = calculate_median(contagem_poly_add) if contagem_poly_add else 0
        poly_mul_chamadas_mediana = calculate_median(contagem_poly_mul) if contagem_poly_mul else 0
        random_poly_chamadas_mediana = calculate_median(contagem_random_poly) if contagem_random_poly else 0
        
        # Exibir resumo estatístico
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
        
        # Restaurar as funções originais
        Saber._poly_add = original_poly_add
        Saber._poly_mul = original_poly_mul
        Saber._random_poly = original_random_poly
        
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
        
        # Garantir que as funções originais sejam restauradas em caso de erro
        if 'original_poly_add' in locals():
            Saber._poly_add = original_poly_add
        if 'original_poly_mul' in locals():
            Saber._poly_mul = original_poly_mul
        if 'original_random_poly' in locals():
            Saber._random_poly = original_random_poly

if __name__ == "__main__":
    main() 