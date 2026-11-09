"""Testes de regressão de segurança — um bloco por vulnerabilidade corrigida.

Cada teste prova que o ataque original deixou de funcionar, para que
uma reintrodução quebre a esteira já na etapa de testes.
"""

import subprocess

import pytest
import requests
from werkzeug.security import generate_password_hash

import config
from modulos import autenticacao, cartoes, credito, notificacoes, relatorios
from modulos.erros import ErroValidacao, RecursoIndisponivel, RecursoNaoEncontrado

# --- 1. Segredos hardcoded ----------------------------------------------------


def test_configuracao_nao_tem_segredos_no_codigo(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        config._obrigatoria("SECRET_KEY")


# --- 2. debug=True --------------------------------------------------------------


def test_debug_desligado_por_padrao():
    assert config.DEBUG is False


# --- 3 e 4. Hash fraco e token previsível ---------------------------------------


def test_hash_de_senha_usa_algoritmo_adaptativo_com_salt():
    primeiro = autenticacao.gerar_hash_senha("password")
    segundo = autenticacao.gerar_hash_senha("password")

    assert primeiro.startswith("scrypt:")
    assert primeiro != segundo  # salt aleatório
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in primeiro  # MD5 de "password"


def test_login_sem_hash_configurado_recusa_qualquer_senha(configuracao):
    configuracao(ADMIN_PASSWORD_HASH="")

    assert autenticacao.validar_login("admin", "password") is False


def test_login_de_usuario_inexistente_e_recusado(configuracao):
    configuracao(ADMIN_PASSWORD_HASH=generate_password_hash("segredo"))

    assert autenticacao.validar_login("outro", "segredo") is False


def test_tokens_de_sessao_sao_unicos_e_longos():
    tokens = {autenticacao.gerar_token_sessao() for _ in range(100)}

    assert len(tokens) == 100
    assert all(len(token) >= 43 for token in tokens)


# --- 5 e 6. SQL Injection --------------------------------------------------------


@pytest.mark.parametrize("entrada", ["1' OR '1'='1", "4111111111111111; DROP TABLE cartoes", "", None])
def test_fatura_rejeita_numero_fora_do_formato(entrada):
    with pytest.raises(ErroValidacao):
        cartoes.consultar_fatura(entrada)


@pytest.mark.parametrize("entrada", ["' OR 1=1 --", "123.456.789-01", None])
def test_busca_de_cartoes_rejeita_cpf_fora_do_formato(entrada):
    with pytest.raises(ErroValidacao):
        cartoes.buscar_cartoes_cliente(entrada)


def test_mascara_numero_do_cartao():
    assert cartoes.mascarar_numero("4111111111111111") == "************1111"


# --- 7. Command Injection no relatório ---------------------------------------------


@pytest.mark.parametrize("formato", ["pdf; cat /etc/passwd", "pdf && id", "$(id)", None])
def test_relatorio_rejeita_formato_fora_da_allowlist(formato):
    with pytest.raises(ErroValidacao):
        relatorios.gerar_relatorio(formato)


def test_relatorio_chama_gerador_sem_shell(monkeypatch):
    chamadas = []

    def run_falso(comando, **opcoes):
        chamadas.append((comando, opcoes))
        return subprocess.CompletedProcess(comando, 0, stdout="conteudo")

    monkeypatch.setattr(relatorios.subprocess, "run", run_falso)

    assert relatorios.gerar_relatorio("pdf") == "conteudo"
    comando, opcoes = chamadas[0]
    assert comando == [config.GERADOR_RELATORIO, "pdf"]
    assert "shell" not in opcoes


def test_relatorio_sinaliza_gerador_indisponivel(configuracao):
    configuracao(GERADOR_RELATORIO="/caminho/que/nao/existe")

    with pytest.raises(RecursoIndisponivel):
        relatorios.gerar_relatorio("csv")


# --- 8. Path Traversal --------------------------------------------------------------


@pytest.fixture
def diretorio_extratos(tmp_path, configuracao):
    extratos = tmp_path / "extratos"
    extratos.mkdir()
    (extratos / "janeiro.txt").write_text("saldo: 100", encoding="utf-8")
    (tmp_path / "segredo.txt").write_text("nao deveria vazar", encoding="utf-8")
    configuracao(EXTRATOS_DIR=str(extratos))
    return extratos


def test_extrato_dentro_do_diretorio_e_lido(diretorio_extratos):
    assert relatorios.baixar_extrato("janeiro.txt") == "saldo: 100"


@pytest.mark.parametrize("nome", ["../segredo.txt", "/etc/passwd", "..\\segredo.txt", "", None])
def test_extrato_bloqueia_escape_do_diretorio(diretorio_extratos, nome):
    with pytest.raises((ErroValidacao, RecursoNaoEncontrado)):
        relatorios.baixar_extrato(nome)


# --- 9. Command Injection no diagnóstico --------------------------------------------


@pytest.mark.parametrize("comando", ["id", "cat /etc/passwd", "uptime; id", None])
def test_diagnostico_nao_executa_comandos_arbitrarios(comando):
    with pytest.raises(ErroValidacao):
        relatorios.executar_diagnostico(comando)


def test_diagnostico_executa_verificacao_permitida():
    resultado = relatorios.executar_diagnostico("horario-utc")

    assert resultado["verificacao"] == "horario-utc"


# --- 10. SSRF --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # metadados de nuvem
        "http://hooks.parceiro.com.br/notificar",  # sem TLS
        "https://localhost/admin",
        "https://hooks.parceiro.com.br:8443/notificar",  # porta não padrão
        "https://usuario:senha@hooks.parceiro.com.br/",
        "https://hooks.parceiro.com.br.atacante.com/",
        "file:///etc/passwd",
        None,
    ],
)
def test_webhook_bloqueia_destino_fora_da_allowlist(configuracao, url):
    configuracao(WEBHOOK_HOSTS_PERMITIDOS=frozenset({"hooks.parceiro.com.br"}))

    with pytest.raises(ErroValidacao):
        notificacoes.enviar_webhook(url, "{}")


def test_webhook_autorizado_e_enviado_sem_seguir_redirect(configuracao, monkeypatch):
    configuracao(WEBHOOK_HOSTS_PERMITIDOS=frozenset({"hooks.parceiro.com.br"}))
    chamadas = []

    class RespostaFalsa:
        status_code = 202

    def post_falso(url, **opcoes):
        chamadas.append(opcoes)
        return RespostaFalsa()

    monkeypatch.setattr(requests, "post", post_falso)

    assert notificacoes.enviar_webhook("https://hooks.parceiro.com.br/notificar", "{}") == 202
    assert chamadas[0]["allow_redirects"] is False


# --- 11. Desserialização insegura -------------------------------------------------------


def test_preferencias_aceitam_objeto_json():
    assert notificacoes.carregar_preferencias_notificacao('{"email": true}') == {"email": True}


@pytest.mark.parametrize(
    "dados",
    [
        "80049500000000000000008c05706f736978",  # payload pickle em hex
        "[1, 2]",
        "nao-e-json",
        "x" * 5000,
        None,
    ],
)
def test_preferencias_rejeitam_formatos_inseguros(dados):
    with pytest.raises(ErroValidacao):
        notificacoes.carregar_preferencias_notificacao(dados)


# --- 12. eval() --------------------------------------------------------------------------


@pytest.mark.parametrize(("expressao", "esperado"), [("5000 * 1.2", 6000.0), ("(1000 + 500) / 3", 500.0), ("-10", -10)])
def test_limite_avalia_aritmetica_simples(expressao, esperado):
    assert credito.calcular_limite_credito(expressao) == pytest.approx(esperado)


@pytest.mark.parametrize(
    "expressao",
    [
        "__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "().__class__.__bases__",
        "9 ** 9 ** 9",  # potência: negação de serviço
        "True + 1",
        "1 / 0",
        "1 +",
        "1" * 101,
        None,
    ],
)
def test_limite_rejeita_codigo_e_expressoes_perigosas(expressao):
    with pytest.raises(ErroValidacao):
        credito.calcular_limite_credito(expressao)
