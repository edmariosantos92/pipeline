"""Simulação de limite de crédito.

A expressão do cliente é interpretada por um avaliador aritmético
restrito sobre a AST: só números e as quatro operações são aceitos.
Qualquer outro nó (nomes, chamadas, atributos, potência) é rejeitado,
então não há como executar código — ao contrário de ``eval()``.
"""

import ast
import operator

from modulos.erros import ErroValidacao

TAMANHO_MAXIMO_EXPRESSAO = 100

_OPERADORES_BINARIOS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}
_OPERADORES_UNARIOS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def calcular_limite_credito(expressao: str | None) -> float:
    """Avalia uma expressão aritmética simples, como ``5000 * 1.2``."""
    if not expressao or len(expressao) > TAMANHO_MAXIMO_EXPRESSAO:
        raise ErroValidacao("expressão ausente ou longa demais")
    try:
        arvore = ast.parse(expressao, mode="eval")
    except SyntaxError as erro:
        raise ErroValidacao("expressão malformada") from erro
    return _avaliar(arvore.body)


def _avaliar(no: ast.AST) -> float:
    if isinstance(no, ast.Constant) and type(no.value) in (int, float):
        return no.value
    if isinstance(no, ast.BinOp) and type(no.op) in _OPERADORES_BINARIOS:
        operacao = _OPERADORES_BINARIOS[type(no.op)]
        try:
            return operacao(_avaliar(no.left), _avaliar(no.right))
        except ZeroDivisionError as erro:
            raise ErroValidacao("divisão por zero") from erro
    if isinstance(no, ast.UnaryOp) and type(no.op) in _OPERADORES_UNARIOS:
        return _OPERADORES_UNARIOS[type(no.op)](_avaliar(no.operand))
    raise ErroValidacao("expressão contém elementos não permitidos")
