class Usuario:
    def __init__(self, id, nome, email, senha, segredo_2fa, criado_em=None, reset_token=None, token_expiracao=None):
        self.id = id
        self.nome = nome
        self.email = email
        self.senha = senha
        self.segredo_2fa = segredo_2fa
        self.criado_em = criado_em
        self.reset_token = reset_token
        self.token_expiracao = token_expiracao