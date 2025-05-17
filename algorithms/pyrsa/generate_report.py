#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import io
from rsa import RSA

def main():
    """
    Executa o algoritmo RSA e salva o relatório de desempenho em arquivo UTF-8
    """
    # Nome do arquivo de relatório
    report_file = "rsa_relatorio.txt"
    
    # Configurar captura de saída
    original_stdout = sys.stdout
    output = io.StringIO()
    sys.stdout = output
    
    try:
        # Criar instância do RSA e executar testes
        rsa = RSA()
        mensagem = "É pau, é pedra, é o fim do caminho\n"
        mensagem += "É um resto de toco, é um pouco sozinho\n"
        mensagem += "É um caco de vidro, é a vida, é o Sol\n"
        mensagem += "É a noite, é a morte, é o laço, é o anzol\n"
        mensagem += "É peroba do campo, é o nó da madeira\n"
        mensagem += "Caingá, candeia, é o Matita Pereira\n"
        mensagem += "É madeira de vento, tombo da ribanceira\n"
        mensagem += "É o mistério profundo, é o queira ou não queira\n"
        mensagem += "É o vento ventando, é o fim da ladeira\n"
        mensagem += "É a viga, é o vão, festa da cumeeira\n"
        mensagem += "É a chuva chovendo, é conversa ribeira\n"
        mensagem += "Das águas de março, é o fim da canseira\n"
        mensagem += "É o pé, é o chão, é a marcha estradeira\n"
        mensagem += "Passarinho na mão, pedra de atiradeira\n"
        mensagem += "É uma ave no céu, é uma ave no chão\n"
        mensagem += "É um regato, é uma fonte, é um pedaço de pão\n"
        mensagem += "É o fundo do poço, é o fim do caminho\n"
        mensagem += "No rosto, o desgosto, é um pouco sozinho\n"
        mensagem += "É um estrepe, é um prego, é uma ponta, é um ponto\n"
        mensagem += "É um pingo pingando, é uma conta, é um conto\n"
        mensagem += "É um peixe, é um gesto, é uma prata brilhando\n"
        mensagem += "É a luz da manhã, é o tijolo chegando\n"
        mensagem += "É a lenha, é o dia, é o fim da picada\n"
        mensagem += "É a garrafa de cana, o estilhaço na estrada\n"
        mensagem += "É o projeto da casa, é o corpo na cama\n"
        mensagem += "É o carro enguiçado, é a lama, é a lama\n"
        mensagem += "É um passo, é uma ponte, é um sapo, é uma rã\n"
        mensagem += "É um resto de mato, na luz da manhã\n"
        mensagem += "São as águas de março fechando o verão\n"
        mensagem += "É a promessa de vida no teu coração\n"
        mensagem += "É uma cobra, é um pau, é João, é José\n"
        mensagem += "É um espinho na mão, é um corte no pé\n"
        mensagem += "São as águas de março fechando o verão\n"
        mensagem += "É a promessa de vida no teu coração\n"
        mensagem += "É um belo horizonte, é uma febre terção\n"
        mensagem += "Pau, edra, im, inho\n"
        mensagem += "Esto, oco, ouco, inho\n"
        mensagem += "Aco, idro, ida, ol, oite, orte, aço, zol\n"
        mensagem += "São as águas de março fechando o verão\n"
        mensagem += "É a promessa de vida no teu coração\n"

        print("\nRELATÓRIO DE DESEMPENHO DO RSA")
        print(f"Data e hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Executar operações RSA
        rsa.generate_keypair()
        rsa.export_keys()
        
        # Obter e imprimir chaves
        e, n = rsa.public_key
        d, _ = rsa.private_key
        
        # Formatar números grandes para melhor legibilidade
        def format_big_num(num):
            return str(num)[:50] + "..." if len(str(num)) > 50 else str(num)
        
        print(f"Chave pública: (e={format_big_num(e)}, n={format_big_num(n)})")
        print(f"Chave privada: (d={format_big_num(d)}, n={format_big_num(n)})")
        
        # Testar criptografia e descriptografia
        encripted_msg = rsa.encripty(mensagem)
        decripted_msg = rsa.decripty(encripted_msg)
        print(f"Mensagem original: {mensagem}")
        print(f"Mensagem descriptografada: {decripted_msg}")
        
        # Imprimir estatísticas detalhadas
        rsa.print_performance_stats()
        
        # Voltar stdout para o original temporariamente para informar ao usuário
        sys.stdout = original_stdout
        print(f"Gerando relatório em: {os.path.abspath(report_file)}")
        
        # Salvar o relatório em arquivo com codificação UTF-8
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(output.getvalue())
            
        print(f"Relatório gerado com sucesso!")
        
    except Exception as e:
        sys.stdout = original_stdout
        print(f"Erro: {str(e)}")
    finally:
        # Restaurar stdout
        sys.stdout = original_stdout

if __name__ == "__main__":
    main() 