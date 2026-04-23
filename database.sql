-- Tabela de usuários
CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    senha BYTEA NOT NULL,
    segredo_2fa VARCHAR(32),
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reset_token TEXT,
    token_expiracao TIMESTAMP
);

-- Tabela de logs de acesso
CREATE TABLE logs_acesso (
    id SERIAL PRIMARY KEY,
    usuario_id INT,
    evento TEXT,
    data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);