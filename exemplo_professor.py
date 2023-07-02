import jwt

f = open("private_key.pem", "r")
privkey = f.read()

print("\n")
print(privkey)
print("\n")

seq_number = int(input("seq_number: "))
matricula = int(input("matricula: "))

payload = {"group": "NONAME","seq_number": seq_number,"seq_max": 4,"matricula": matricula}

jwt_enc = jwt.encode(payload, privkey.encode('utf-8'), algorithm='RS256')

print("\n")
print(jwt_enc)

pub_key = open('public_key.pem','r').read()

print("\n")
print(pub_key)

decode = jwt.decode(jwt_enc, key=pub_key, algorithms=["RS256"], options={"verify_signature":True})

print("\n")
print(decode)
print("\n")