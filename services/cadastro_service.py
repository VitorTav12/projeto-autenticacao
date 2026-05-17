# services/cadastro_service.py
# Coloque este arquivo dentro da pasta services/

import pyotp
import qrcode
import io
import base64
import argon2
from argon2 import PasswordHasher
from dao import usuario_dao

ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def criar_usuario(nome: str, email: str, senha: str,
                  versao_consentimento: str, data_consentimento: str):
    """
    Cria um novo usuário no banco.
    - email sempre em minúsculo
    - senha com hash Argon2
    - segredo 2FA gerado automaticamente
    - consentimento LGPD registrado com data e versão
    Retorna: (sucesso, mensagem, user_id, segredo_2fa)
    """
    # Verificar se email já existe
    if usuario_dao.buscar_por_email(email):
        return False, "E-mail já cadastrado.", None, None

    # Hash da senha com Argon2
    senha_hash = ph.hash(senha)

    # Gerar segredo TOTP para 2FA
    segredo_2fa = pyotp.random_base32()

    # Inserir no banco
    user_id = usuario_dao.inserir_usuario(
        nome=nome,
        email=email,                        # já em lowercase
        senha_hash=senha_hash,
        segredo_2fa=segredo_2fa,
        versao_consentimento=versao_consentimento,
        data_consentimento=data_consentimento,
    )

    if not user_id:
        return False, "Erro ao criar usuário. Tente novamente.", None, None

    return True, "Usuário criado com sucesso.", user_id, segredo_2fa


def gerar_qr_url(user_id: int, segredo: str) -> str:
    """
    Gera a URL de dados (data URI) do QR Code para o Google Authenticator.
    """
    # Busca email do usuário para montar o label do QR
    usuario = usuario_dao.buscar_por_id(user_id)
    email = usuario.email if usuario else f"usuario_{user_id}"

    uri = pyotp.totp.TOTP(segredo).provisioning_uri(
        name=email,
        issuer_name="SistemaAutenticacao"
    )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{b64}"