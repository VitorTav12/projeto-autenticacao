# dao/usuario_dao.py

from config import get_connection
from models.usuario import Usuario

def buscar_por_email(email: str):
    """Busca usuário pelo email (sempre em minúsculo)."""
    email = email.lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, nome, email, senha, segredo_2fa FROM usuarios WHERE email = %s",
                (email,)
            )
            row = cur.fetchone()
            return Usuario(*row) if row else None
    finally:
        conn.close()
def buscar_usuario_por_email(email: str):
    return buscar_por_email(email)


def buscar_por_id(user_id: int):
    """Busca usuário pelo ID."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, nome, email, senha, segredo_2fa FROM usuarios WHERE id = %s",
                (user_id,)
            )
            row = cur.fetchone()
            return Usuario(*row) if row else None
    finally:
        conn.close()


def buscar_por_token(token: str):
    """Busca usuário pelo token de reset de senha."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, nome, email, senha, segredo_2fa, token_expiracao
                   FROM usuarios WHERE reset_token = %s""",
                (token,)
            )
            row = cur.fetchone()
            if not row:
                return None
            user = Usuario(*row[:5])
            user.token_expiracao = row[5]
            return user
    finally:
        conn.close()
def inserir_usuario(nome: str, email: str, senha_hash: str,
                    segredo_2fa: str, versao_consentimento: str,
                    data_consentimento: str):
    """
    Insere novo usuário com consentimento LGPD.
    Email salvo sempre em minúsculo.
    Retorna o ID gerado ou None em caso de erro.
    """
    email = email.lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usuarios
                    (nome, email, senha, segredo_2fa,
                     lgpd_aceite, lgpd_versao, lgpd_data_aceite)
                VALUES (%s, %s, %s, %s, TRUE, %s, %s)
                RETURNING id
                """,
                (nome, email, senha_hash, segredo_2fa,
                 versao_consentimento, data_consentimento)
            )
            user_id = cur.fetchone()[0]
            conn.commit()
            return user_id
    except Exception as e:
        conn.rollback()
        print(f"[ERRO] inserir_usuario: {e}")
        return None
    finally:
        conn.close()
def salvar_token(user_id: int, token: str, expiracao):
    """Salva token de reset de senha."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET reset_token=%s, token_expiracao=%s WHERE id=%s",
                (token, expiracao, user_id)
            )
            conn.commit()
    finally:
        conn.close()


def atualizar_token_reset(email: str, token: str, expiracao):
    """Alias usado por outros módulos."""
    user = buscar_por_email(email)
    if user:
        salvar_token(user.id, token, expiracao)


def invalidar_token(user_id: int):
    """Remove o token de reset após uso."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET reset_token=NULL, token_expiracao=NULL WHERE id=%s",
                (user_id,)
            )
            conn.commit()
    finally:
        conn.close()
def atualizar_senha(user_id: int, nova_senha_hash):
    """Atualiza a senha do usuário."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET senha=%s WHERE id=%s",
                (nova_senha_hash, user_id)
            )
            conn.commit()
    finally:
        conn.close()
def excluir_usuario(user_id: int):
    """
    Exclui os dados pessoais do usuário (nome, email, senha, 2FA, consentimento).
    Os logs de acesso são anonimizados (usuario_id vira NULL) por obrigação legal.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Anonimiza os logs (mantém o histórico sem vínculo com o usuário)
            cur.execute(
                "UPDATE logs_acesso SET usuario_id = NULL WHERE usuario_id = %s",
                (user_id,)
            )
            # Remove o usuário e todos os seus dados pessoais
            cur.execute(
                "DELETE FROM usuarios WHERE id = %s",
                (user_id,)
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[ERRO] excluir_usuario: {e}")
    finally:
        conn.close()
def buscar_dados_titular(user_id: int):
    """Retorna todos os dados pessoais do titular (4.8)."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT nome, email, criado_em,
                          lgpd_aceite, lgpd_versao, lgpd_data_aceite
                   FROM usuarios WHERE id = %s""",
                (user_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "nome":            row[0],
                "email":           row[1],
                "criado_em":       str(row[2]) if row[2] else None,
                "lgpd_aceite":     row[3],
                "lgpd_versao":     row[4],
                "lgpd_data_aceite": str(row[5]) if row[5] else None,
            }
    finally:
        conn.close()


def buscar_logs_usuario(user_id: int):
    """Retorna os logs de acesso do usuário (5.4)."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT evento, data_hora FROM logs_acesso
                   WHERE usuario_id = %s
                   ORDER BY data_hora DESC LIMIT 50""",
                (user_id,)
            )
            rows = cur.fetchall()
            return [{"evento": r[0], "data_hora": str(r[1])} for r in rows]
    finally:
        conn.close()