from seguranca.primitivas import PrimitivasServidor as P

h, s = P.gerar_hash_senha("minhasenha")
print("Hash:", h[:50], "...")
print("Correta:", P.verificar_senha("minhasenha", h, s))
print("Errada:", P.verificar_senha("outra", h, s))
print("Argon2 usado:", h.startswith("$argon2"))