import jwt
import socket
import re

# Solicitação dos parâmetros de conexão
UDP_IP = str(input("Endereço UDP (gersoncamillo.seg.br): "))
UDP_PORT = int(input("Porta UDP (34567): "))
grupo = str(input("Nome do grupo (noname): ")).upper()
num_seq = 0
seq_max = int(input("Quantidade de integrantes (4): "))
matricula = 00000000

# Função para salvar a resposta do servidor em um arquivo de log
def salvar_resposta_em_arquivo(resposta_bruta, resposta_decodificada, valida=True):
    with open('logs.txt', 'a') as arquivo:
        arquivo.write(resposta_bruta)
        arquivo.write('\n')
        arquivo.write('Verificação: {}\n'.format('OK\nArquivo decodificado:' if valida else 'NOT_OK'))
        arquivo.write(resposta_decodificada)
        arquivo.write('\n\n')

# Carregamento das chaves públicas e privadas
with open("private_key.pem", "r") as f:
    chave_privada = f.read()

with open("public_key.pem", "r") as f:
    chave_pub = f.read()

with open("secret_key.pem", "r") as f:
    chave_secreta = f.read()

# Laço principal do programa
while True:
    # Verifica se já foi digitada alguma matrícula e oferece sugestão com base em um dicionário
    if num_seq != 0:
        sugestoes = {
            1: "20150466",
            2: "21106346",
            3: "19250497",
            4: "20104998"
        }
        sugestao = sugestoes.get(num_seq, "")
        if sugestao:
            print(f"\nSugestão: {sugestao}")

        matricula = int(input(f"Digite a {num_seq}ª matrícula: "))

    # Preparação dos dados para o token JWT
    payload = {
        "group": grupo,
        "seq_number": num_seq,
        "seq_max": seq_max,
        "matricula": matricula,
    }

    # Codificação e assinatura do token JWT
    jwt_enc = jwt.encode(payload, chave_privada.encode('utf-8'), algorithm='RS256')
    jwt_enc = jwt_enc.encode('utf-8')

    # Inicialização do socket UDP para enviar o token ao servidor
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(jwt_enc, (UDP_IP, UDP_PORT))
        sock.settimeout(2)

        try:
            # Aguarda a resposta do servidor e decodifica o token recebido
            data, addr = sock.recvfrom(1024)
            jwt_resposta = data.decode('utf-8')

            try:
                # Verifica a validade da assinatura do token decodificado
                jwt_decodificado = jwt.decode(jwt_resposta, key=chave_secreta, algorithms=["HS256"], options={"verify_signature": True})
                jwt_decodificado_str = str(jwt_decodificado)
                salvar_resposta_em_arquivo(jwt_resposta, jwt_decodificado_str, True)

                # Extrai o próximo número de sequência do token decodificado para continuar a iteração
                match = re.search(r"'next_number':\s*([0-9]+)", jwt_decodificado_str)
                if match:
                    prox_numero = int(match.group(1))
                    num_seq = prox_numero

                # Verifica se chegou ao final da sequência
                if num_seq == 0:
                    break

            except jwt.InvalidSignatureError:
                # Caso a assinatura seja inválida, registra a resposta no arquivo de log sem decodificação
                salvar_resposta_em_arquivo(jwt_resposta, "", False)

        except socket.timeout:
            # Caso ocorra timeout na comunicação com o servidor
            print("Servidor não disponível!")

    # Solicita ao usuário se deseja enviar mais um token
    outro_token = input("Desejas enviar mais um token? (s/n): ")
    if outro_token.lower() != "s":
        break