import jwt
import socket

f = open("private_key.pem", "r")
privkey = f.read()
f.close()

print("\n")
print(privkey)
print("\n")

seq_number = int(input("seq_number: "))
matricula = int(input("matricula: "))

payload = {
"group": "NONAME",
"seq_number": seq_number,
"seq_max": 4,
"matricula": matricula,
}

print("\n")
print(payload)

jwt_enc = jwt.encode(payload, privkey.encode('utf-8'), algorithm='RS256')

print("\n")
print(jwt_enc)

jwt_enc = bytes(jwt_enc.encode('utf-8'))

print("\n")
print(jwt_enc)

UDP_IP = 'gersoncamillo.seg.br'
UDP_PORT = 34567

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(jwt_enc, (UDP_IP, UDP_PORT))
sock.settimeout(2)

try:
    data, addr = sock.recvfrom(1024)
    jwt_answer = data.decode('utf-8')

except socket.timeout:
    print("\n")
    print("Erro ao enviar/receber dados")
    sock.close()

pub_key = open('public_key.pem', 'r').read()

print("\n")
print(pub_key)
print("\n")

decode = jwt.decode(jwt_answer, key=pub_key, algorithms=["RS256"], options={"verify_signature": True})

print("Decoded:")
print(decode)
print("\n")

with open('report.txt', 'a') as arquivo:
    arquivo.write('\n'.join(decode))
    arquivo.write('\n')