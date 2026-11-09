"""Testes da camada HTTP: contrato das rotas e controles transversais."""

import sqlite3

import pytest
from werkzeug.security import generate_password_hash

from app import CABECALHOS_SEGURANCA


def test_saude_responde_ok(cliente):
    resposta = cliente.get("/saude")

    assert resposta.status_code == 200
    assert resposta.get_json() == {"status": "ok"}


def test_toda_resposta_traz_cabecalhos_de_seguranca(cliente):
    resposta = cliente.get("/rota-inexistente")

    assert resposta.status_code == 404
    for cabecalho, valor in CABECALHOS_SEGURANCA.items():
        assert resposta.headers[cabecalho] == valor


def test_login_valido_retorna_token(cliente, configuracao):
    configuracao(ADMIN_PASSWORD_HASH=generate_password_hash("senha-correta"))

    resposta = cliente.post("/login", data={"usuario": "admin", "senha": "senha-correta"})

    assert resposta.status_code == 200
    assert len(resposta.get_json()["token"]) >= 43


def test_login_invalido_retorna_401(cliente, configuracao):
    configuracao(ADMIN_PASSWORD_HASH=generate_password_hash("senha-correta"))

    resposta = cliente.post("/login", data={"usuario": "admin", "senha": "errada"})

    assert resposta.status_code == 401


def test_entrada_invalida_retorna_400_em_json(cliente):
    resposta = cliente.get("/simular-limite", query_string={"expressao": "__import__('os')"})

    assert resposta.status_code == 400
    assert "erro" in resposta.get_json()


def test_erro_inesperado_nao_vaza_detalhes(cliente, configuracao, tmp_path):
    configuracao(DB_PATH=str(tmp_path / "vazio.db"))  # banco sem a tabela cartoes

    resposta = cliente.get("/fatura", query_string={"numero_cartao": "4111111111111111"})

    assert resposta.status_code == 500
    assert resposta.get_json() == {"erro": "erro interno"}


@pytest.fixture
def banco_com_cartao(tmp_path, configuracao):
    caminho = tmp_path / "cartoes.db"
    with sqlite3.connect(caminho) as conexao:
        conexao.execute("CREATE TABLE cartoes (numero TEXT, fatura REAL, cpf_titular TEXT)")
        conexao.execute("INSERT INTO cartoes VALUES ('4111111111111111', 1500.5, '12345678901')")
    configuracao(DB_PATH=str(caminho))


def test_fatura_existente_retorna_numero_mascarado(cliente, banco_com_cartao):
    resposta = cliente.get("/fatura", query_string={"numero_cartao": "4111111111111111"})

    assert resposta.get_json() == {"numero": "************1111", "fatura": 1500.5}


def test_fatura_inexistente_retorna_404(cliente, banco_com_cartao):
    resposta = cliente.get("/fatura", query_string={"numero_cartao": "5555555555554444"})

    assert resposta.status_code == 404
