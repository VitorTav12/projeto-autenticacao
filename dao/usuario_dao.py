from config import get_connection
from models.usuario import Usuario


def buscar_usuario_por_email(email):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, nome, email, senha, segredo_2fa, criado_em, reset_token, token_expiracao
        FROM usuarios 
        WHERE email = %s
    """, (email,))
    
    result = cursor.fetchone()
    conn.close()

    if result:
        return Usuario(*result)
    return None


def salvar_token(usuario_id, token, expiracao):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios 
        SET reset_token = %s, token_expiracao = %s
        WHERE id = %s
    """, (token, expiracao, usuario_id))
    conn.commit()
    conn.close()


def buscar_por_token(token):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, nome, email, senha, segredo_2fa, criado_em, reset_token, token_expiracao
        FROM usuarios
        WHERE reset_token = %s
    """, (token,))
    
    result = cursor.fetchone()
    conn.close()

    if result:
        return Usuario(*result)
    return None


def atualizar_senha(usuario_id, nova_senha):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET senha = %s WHERE id = %s
    """, (nova_senha, usuario_id))
    conn.commit()
    conn.close()


def invalidar_token(usuario_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios 
        SET reset_token = NULL, token_expiracao = NULL
        WHERE id = %s
    """, (usuario_id,))
    conn.commit()
    conn.close()