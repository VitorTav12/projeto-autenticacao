import bcrypt
import pyotp
import time
import secrets
from datetime import datetime, timedelta

from dao.usuario_dao import (
    buscar_usuario_por_email,
    salvar_token,
    buscar_por_token,
    atualizar_senha,
    invalidar_token
)

from config import get_connection

tentativas = {}

def registrar_log(usuario_id, evento):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs_acesso (usuario_id, evento) VALUES (%s, %s)",
            (usuario_id, evento)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao salvar log: {e}")


# ---------------- LOGIN ---------------- #

def verificar_senha(email, senha):
    agora = time.time()
    dados = tentativas.get(email, {"erros": 0, "bloqueado_ate": 0})

    if agora < dados["bloqueado_ate"]:
        return False, int(dados["bloqueado_ate"] - agora), None

    user = buscar_usuario_por_email(email)
    if not user:
        return False, "E-mail não cadastrado", None

    senha_db = bytes(user.senha) if isinstance(user.senha, memoryview) else user.senha
    
    if bcrypt.checkpw(senha.encode('utf-8'), senha_db):
        tentativas[email] = {"erros": 0, "bloqueado_ate": 0}
        registrar_log(user.id, "Login: Senha correta (Fase 1)")
        return True, "Sucesso", user
    else:
        novos_erros = dados["erros"] + 1
        bloqueio_ate = 0

        if novos_erros >= 3:
            bloqueio_ate = agora + 180
            registrar_log(user.id, "BLOQUEIO: 3 falhas atingidas.")
            resultado_msg = 180
        else:
            registrar_log(user.id, f"FALHA: Senha incorreta ({novos_erros}/3)")
            resultado_msg = f"Senha incorreta ({novos_erros}/3)"
        
        tentativas[email] = {"erros": novos_erros, "bloqueado_ate": bloqueio_ate}
        return False, resultado_msg, None


def verificar_2fa(user_id, segredo, codigo):
    totp = pyotp.TOTP(segredo)
    if totp.verify(codigo, valid_window=2):
        registrar_log(user_id, "2FA validado")
        return True
    registrar_log(user_id, "FALHA: 2FA inválido")
    return False


# ---------------- RECUPERAÇÃO ---------------- #

def gerar_token():
    return secrets.token_urlsafe(32)


def gerar_expiracao():
    return datetime.utcnow() + timedelta(minutes=15)


def solicitar_recuperacao(email):
    user = buscar_usuario_por_email(email)

    if not user:
        return True

    token = gerar_token()
    expiracao = gerar_expiracao()

    salvar_token(user.id, token, expiracao)

    print(f"LINK PARA RESET: http://localhost:5000/resetar/{token}")

    registrar_log(user.id, "Recuperação solicitada")

    return True


def validar_token(token):
    user = buscar_por_token(token)

    if not user or not user.token_expiracao:
        return None, "Token inválido"

    if user.token_expiracao < datetime.utcnow():
        registrar_log(user.id, "Token expirado")
        return None, "Token expirado"

    return user, None


def resetar_senha(token, nova_senha, codigo_2fa):
    user, erro = validar_token(token)

    if erro:
        return erro

    # 🔐 NOVO: valida 2FA
    if not verificar_2fa(user.id, user.segredo_2fa, codigo_2fa):
        registrar_log(user.id, "Falha reset: 2FA inválido")
        return "Código 2FA inválido"

    senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

    atualizar_senha(user.id, senha_hash)
    invalidar_token(user.id)

    registrar_log(user.id, "Senha redefinida com 2FA")

    return "Senha alterada com sucesso"