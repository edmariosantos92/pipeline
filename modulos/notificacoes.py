"""Notificações e integrações externas.

Webhooks só saem para hosts HTTPS de uma allowlist (contra SSRF) e as
preferências do cliente trafegam em JSON, nunca em formato que execute
código ao ser desserializado.
"""

import json
from urllib.parse import urlsplit

import requests

import config
from modulos.erros import ErroValidacao, RecursoIndisponivel

TEMPO_LIMITE_WEBHOOK_SEGUNDOS = 5
TAMANHO_MAXIMO_PREFERENCIAS = 4096


def enviar_webhook(url_destino: str | None, payload: str | None) -> int:
    """Envia o payload ao webhook autorizado e devolve o status HTTP."""
    _validar_destino_webhook(url_destino or "")
    try:
        resposta = requests.post(
            url_destino,
            data=payload or "",
            timeout=TEMPO_LIMITE_WEBHOOK_SEGUNDOS,
            allow_redirects=False,  # um redirect poderia levar para a rede interna
        )
    except requests.RequestException as erro:
        raise RecursoIndisponivel("falha ao entregar o webhook") from erro
    return resposta.status_code


def carregar_preferencias_notificacao(dados: str | None) -> dict:
    """Interpreta as preferências enviadas pelo cliente (objeto JSON)."""
    if not dados or len(dados) > TAMANHO_MAXIMO_PREFERENCIAS:
        raise ErroValidacao("preferências ausentes ou grandes demais")
    try:
        preferencias = json.loads(dados)
    except json.JSONDecodeError as erro:
        raise ErroValidacao("preferências devem ser um JSON válido") from erro
    if not isinstance(preferencias, dict):
        raise ErroValidacao("preferências devem ser um objeto JSON")
    return preferencias


def _validar_destino_webhook(url: str) -> None:
    partes = urlsplit(url)
    autorizado = (
        partes.scheme == "https"
        and partes.hostname in config.WEBHOOK_HOSTS_PERMITIDOS
        and partes.port in (None, 443)
        and not partes.username
        and not partes.password
    )
    if not autorizado:
        raise ErroValidacao("destino de webhook não autorizado")
