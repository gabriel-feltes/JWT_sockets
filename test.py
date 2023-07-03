import jwt
import socket

SECRET_KEY = b'dec7557-socket-udp-with-jwt'

def save_response_to_file(response, is_valid):
    with open('report.txt', 'a') as arquivo:
        arquivo.write(response)
        arquivo.write('\n')
        arquivo.write('Verification: {}\n'.format('OK' if is_valid else 'NOT_OK'))
        arquivo.write('\n')

# Read the private key
with open("private_key.pem", "r") as f:
    privkey = f.read()

# Read the public key
with open("public_key.pem", "r") as f:
    pub_key = f.read()

UDP_IP = input("UDP IP: ")
UDP_PORT = int(input("UDP Port: "))

while True:
    payloads = []

    for _ in range(4):
        seq_number = int(input("seq_number: "))
        matricula = int(input("matricula: "))

        payload = {
            "group": "NONAME",
            "seq_number": seq_number,
            "seq_max": 4,
            "matricula": matricula,
        }
        payloads.append(payload)

    for payload in payloads:
        jwt_enc = jwt.encode(payload, privkey.encode('utf-8'), algorithm='RS256')
        jwt_enc = jwt_enc.encode('utf-8')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(jwt_enc, (UDP_IP, UDP_PORT))
        sock.settimeout(2)

        try:
            data, addr = sock.recvfrom(1024)
            jwt_answer = data.decode('utf-8')

            try:
                decoded_jwt = jwt.decode(jwt_answer, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": True})
                save_response_to_file(str(decoded_jwt), True)
            except jwt.InvalidSignatureError:
                save_response_to_file(jwt_answer, False)
        except socket.timeout:
            print("\n")
            print("Error sending/receiving data")
        finally:
            sock.close()

    another_token = input("Do you want to send another JWT token? (y/n): ")
    if another_token.lower() != "y":
        break