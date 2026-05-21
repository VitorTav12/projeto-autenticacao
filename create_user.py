import bcrypt
import pyotp
import qrcode
from config import get_connection

nome = "Igor"
email = "igor@email.com"
senha_texto = "sccp1910"

senha_hash = bcrypt.hashpw(senha_texto.encode(), bcrypt.gensalt())
segredo = pyotp.random_base32()

conn = get_connection()
cursor = conn.cursor()

cursor.execute(
    "INSERT INTO usuarios (nome, email, senha, segredo_2fa) VALUES (%s, %s, %s, %s)",
    (nome, email, senha_hash, segredo)
)

conn.commit()
conn.close()

uri = pyotp.TOTP(segredo).provisioning_uri(name=email, issuer_name="SistemaEmpresa")
qrcode.make(uri).save("qrcode.png")

print("\n" + "="*40)
print("✅ USUÁRIO CRIADO COM SUCESSO!")
print("👉 Por favor, escaneie o arquivo 'qrcode.png'")
print("   que apareceu na pasta do seu projeto")
print("   usando o Authenticator.")
print("="*40 + "\n")