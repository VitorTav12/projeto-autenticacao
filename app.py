from flask import Flask, render_template, request, redirect, url_for, session, flash
from services import auth_service
from services import cadastro_service
from services.auth_service import solicitar_recuperacao, resetar_senha, validar_token
from datetime import timedelta
import time

app = Flask(__name__)
app.secret_key = 'chave_secreta_projeto_integrador_2026'
app.permanent_session_lifetime = timedelta(minutes=5)

# ──────────────────────────────────────────────
#  LOGIN
# ──────────────────────────────────────────────

@app.route('/')
def index():
    agora = time.time()
    bloqueio_ate = session.get('bloqueio_ate', 0)
    restante = 0
    if agora < bloqueio_ate:
        restante = int(bloqueio_ate - agora)
    return render_template('login.html', tempo_restante=restante)


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    senha = request.form.get('senha')

    sucesso, mensagem, user = auth_service.verificar_senha(email, senha)

    if sucesso:
        session.permanent = True
        session.pop('bloqueio_ate', None)
        session['pre_user_id']  = user.id
        session['pre_segredo']  = user.segredo_2fa
        session['pre_nome']     = user.nome
        return redirect(url_for('auth_2fa'))

    if isinstance(mensagem, int):
        session['bloqueio_ate'] = time.time() + mensagem
    else:
        flash(mensagem)

    return redirect(url_for('index'))


@app.route('/2fa')
def auth_2fa():
    if 'pre_user_id' not in session:
        return redirect(url_for('index'))
    return render_template('auth_2fa.html')


@app.route('/validar-2fa', methods=['POST'])
def validar_2fa():
    codigo = request.form.get('codigo')
    if 'pre_user_id' not in session:
        return redirect(url_for('index'))

    if auth_service.verificar_2fa(session['pre_user_id'], session['pre_segredo'], codigo):
        session['usuario_id']   = session['pre_user_id']
        session['usuario_nome'] = session['pre_nome']
        session.pop('pre_user_id', None)
        session.pop('pre_segredo', None)
        return redirect(url_for('home'))
    else:
        flash("Código 2FA inválido!")
        return redirect(url_for('auth_2fa'))


@app.route('/home')
def home():
    if 'usuario_id' not in session:
        return redirect(url_for('index'))
    return render_template('home.html', nome=session['usuario_nome'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ──────────────────────────────────────────────
#  RECUPERAÇÃO DE SENHA
# ──────────────────────────────────────────────

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'GET':
        return render_template('recuperar.html')

    email = request.form.get('email')
    solicitar_recuperacao(email)
    flash("Verifique o link no terminal.")
    return redirect(url_for('index'))


@app.route('/resetar/<token>', methods=['GET', 'POST'])
def resetar(token):
    if request.method == 'GET':
        user, erro = validar_token(token)
        if erro:
            flash(erro)
            return redirect(url_for('index'))
        return render_template('resetar.html', token=token)

    nova_senha = request.form.get('senha')
    codigo     = request.form.get('codigo')
    resultado  = resetar_senha(token, nova_senha, codigo)
    flash(resultado)
    return redirect(url_for('index'))

# ──────────────────────────────────────────────
#  CADASTRO + SETUP 2FA
# ──────────────────────────────────────────────

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'GET':
        return render_template('cadastro.html')

    nome                 = request.form.get('nome', '').strip()
    email                = request.form.get('email', '').strip().lower()
    senha                = request.form.get('senha', '')
    lgpd_aceite          = request.form.get('lgpd_aceite')
    versao_consentimento = request.form.get('versao_consentimento', '1.0')
    data_consentimento   = request.form.get('data_consentimento', '')

    if not nome or not email or not senha:
        flash("Preencha todos os campos.")
        return redirect(url_for('cadastro'))

    if '@' not in email:
        flash("E-mail inválido: deve conter '@'.")
        return redirect(url_for('cadastro'))

    if len(senha) < 8:
        flash("A senha deve ter no mínimo 8 caracteres.")
        return redirect(url_for('cadastro'))

    if not lgpd_aceite:
        flash("Você precisa aceitar os termos da LGPD.")
        return redirect(url_for('cadastro'))

    sucesso, mensagem, user_id, segredo_2fa = cadastro_service.criar_usuario(
        nome=nome,
        email=email,
        senha=senha,
        versao_consentimento=versao_consentimento,
        data_consentimento=data_consentimento,
    )

    if not sucesso:
        flash(mensagem)
        return redirect(url_for('cadastro'))

    session['setup_user_id'] = user_id
    session['setup_segredo']  = segredo_2fa
    return redirect(url_for('setup_2fa'))


@app.route('/cadastro/setup-2fa')
def setup_2fa():
    if 'setup_user_id' not in session:
        return redirect(url_for('cadastro'))

    segredo = session['setup_segredo']
    qr_url  = cadastro_service.gerar_qr_url(session['setup_user_id'], segredo)
    return render_template('setup_2fa.html', qr_url=qr_url, segredo=segredo)


@app.route('/cadastro/confirmar-2fa', methods=['POST'])
def confirmar_2fa_cadastro():
    if 'setup_user_id' not in session:
        return redirect(url_for('cadastro'))

    codigo  = request.form.get('codigo', '')
    user_id = session['setup_user_id']
    segredo = session['setup_segredo']

    if auth_service.verificar_2fa(user_id, segredo, codigo):
        session.pop('setup_user_id', None)
        session.pop('setup_segredo', None)
        flash("Cadastro concluído! Faça login para continuar.")
        return redirect(url_for('index'))
    else:
        flash("Código 2FA incorreto. Tente novamente.")
        return redirect(url_for('setup_2fa'))

# ──────────────────────────────────────────────
#  EXCLUSÃO DE CONTA (LGPD Art. 18)
# ──────────────────────────────────────────────

@app.route('/excluir-conta', methods=['POST'])
def excluir_conta():
    if 'usuario_id' not in session:
        return redirect(url_for('index'))

    user_id = session['usuario_id']

    from dao import usuario_dao
    usuario_dao.excluir_usuario(user_id)

    session.clear()
    flash("Seus dados foram excluídos com sucesso.")
    return redirect(url_for('index'))

# ──────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True)