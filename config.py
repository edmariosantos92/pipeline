"""Configuração do Simulador de Cartões de Crédito.

Todos os valores vêm de variáveis de ambiente — nenhum segredo fica no
código-fonte. Em produção eles chegam pelo Secret do Kubernetes criado
pela esteira; localmente, pelo ambiente do desenvolvedor.
"""

import os


def _obrigatoria(nome: str) -> str:
    """Lê uma variável obrigatória e falha cedo, na subida, se faltar."""
    valor = os.getenv(nome)
    if not valor:
        raise RuntimeError(f"Variável de ambiente obrigatória ausente: {nome}")
    return valor


def _conjunto(nome: str) -> frozenset[str]:
    """Lê uma lista separada por vírgulas como conjunto normalizado."""
    itens = os.getenv(nome, "").split(",")
    return frozenset(item.strip().lower() for item in itens if item.strip())


# Desligado por padrão: o modo debug expõe o console interativo do Werkzeug.
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

SECRET_KEY = _obrigatoria("SECRET_KEY")

# Hash (formato Werkzeug/scrypt) da senha do usuário "admin". Sem ele,
# nenhum login é aceito. Gere com: python scripts/gerar_hash_senha.py
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")

DB_PATH = os.getenv("DB_PATH", "cartoes.db")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
API_KEY_BANDEIRA = os.getenv("API_KEY_BANDEIRA", "")

EXTRATOS_DIR = os.getenv("EXTRATOS_DIR", "/var/extratos")
GERADOR_RELATORIO = os.getenv("GERADOR_RELATORIO", "/usr/local/bin/gerar-relatorio")

# Hosts autorizados a receber webhooks (allowlist contra SSRF).
WEBHOOK_HOSTS_PERMITIDOS = _conjunto("WEBHOOK_HOSTS_PERMITIDOS")
