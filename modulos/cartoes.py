"""Consulta de cartões e faturas.

Toda consulta é parametrizada e toda entrada é validada contra um
formato estrito antes de chegar ao banco. O número do cartão nunca é
devolvido por completo.
"""

import re
import sqlite3
from contextlib import closing

import config
from modulos.erros import ErroValidacao

_NUMERO_CARTAO = re.compile(r"\d{13,19}")
_CPF = re.compile(r"\d{11}")


def consultar_fatura(numero_cartao: str | None) -> dict | None:
    """Retorna a fatura do cartão, ou ``None`` se ele não existir."""
    numero = _validar(numero_cartao, _NUMERO_CARTAO, "numero_cartao")
    linhas = _consultar("SELECT numero, fatura FROM cartoes WHERE numero = ?", (numero,))
    return _apresentar(linhas[0]) if linhas else None


def buscar_cartoes_cliente(cpf: str | None) -> list[dict]:
    """Lista os cartões do titular identificado pelo CPF."""
    cpf_valido = _validar(cpf, _CPF, "cpf")
    linhas = _consultar("SELECT numero, fatura FROM cartoes WHERE cpf_titular = ?", (cpf_valido,))
    return [_apresentar(linha) for linha in linhas]


def mascarar_numero(numero: str) -> str:
    """Mantém apenas os quatro últimos dígitos visíveis."""
    return "*" * (len(numero) - 4) + numero[-4:]


def _validar(valor: str | None, formato: re.Pattern, campo: str) -> str:
    if not valor or not formato.fullmatch(valor):
        raise ErroValidacao(f"{campo} inválido")
    return valor


def _consultar(sql: str, parametros: tuple) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(config.DB_PATH)) as conexao:
        conexao.row_factory = sqlite3.Row
        return conexao.execute(sql, parametros).fetchall()


def _apresentar(linha: sqlite3.Row) -> dict:
    return {"numero": mascarar_numero(linha["numero"]), "fatura": linha["fatura"]}
