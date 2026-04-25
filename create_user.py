import bcrypt
import pyotp
import qrcode
from config import get_connection

# Dados do usuário
nome = "Igor"
email = "igor@email.com"
senha_texto = "sccp1910"

# Geração de hash seguro e segredo 2FA
senha_hash = bcrypt.hashpw(senha_texto.encode(), bcrypt.gensalt())
segredo = pyotp.random_base32()

# Conexão e inserção no banco de dados
conn = get_connection()
cursor = conn.cursor()

cursor.execute(
    "INSERT INTO usuarios (nome, email, senha, segredo_2fa) VALUES (%s, %s, %s, %s)",
    (nome, email, senha_hash, segredo)
)

conn.commit()
conn.close()

# Geração do QR Code para o Authenticator
uri = pyotp.TOTP(segredo).provisioning_uri(name=email, issuer_name="SistemaEmpresa")
qrcode.make(uri).save("qrcode.png")

# Mensagem atualizada para o terminal
print("\n" + "="*40)
print("✅ USUÁRIO CRIADO COM SUCESSO!")
print("👉 Por favor, escaneie o arquivo 'qrcode.png'")
print("   que apareceu na pasta do seu projeto")
print("   usando o Authenticator.")
print("="*40 + "\n")