"""Autenticação do Simulador de Cartões de Crédito.

Senhas são verificadas com hash adaptativo (scrypt, via Werkzeug) e
tokens de sessão vêm de um gerador criptograficamente seguro.
"""

import secrets

from werkzeug.security import check_password_hash, generate_password_hash

import config

USUARIO_ADMIN = "admin"

# Hash de uma senha aleatória, usado quando o usuário não existe: a
# verificação custa o mesmo tempo e não revela quais usuários existem.
_HASH_FICTICIO = generate_password_hash(secrets.token_urlsafe(32))


def gerar_hash_senha(senha: str) -> str:
    """Gera o hash da senha com scrypt e salt aleatório."""
    return generate_password_hash(senha)


def validar_login(usuario: str | None, senha: str | None) -> bool:
    """Valida as credenciais em tempo constante em relação ao usuário."""
    if not usuario or not senha:
        return False
    hash_armazenado = _hash_do_usuario(usuario)
    senha_confere = check_password_hash(hash_armazenado or _HASH_FICTICIO, senha)
    return hash_armazenado is not None and senha_confere


def gerar_token_sessao() -> str:
    """Gera um token de sessão imprevisível (256 bits de entropia)."""
    return secrets.token_urlsafe(32)


def _hash_do_usuario(usuario: str) -> str | None:
    if usuario == USUARIO_ADMIN and config.ADMIN_PASSWORD_HASH:
        return config.ADMIN_PASSWORD_HASH
    return None
