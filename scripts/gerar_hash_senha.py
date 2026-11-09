"""Gera o valor de ADMIN_PASSWORD_HASH sem a senha passar pelo shell.

Uso:  python scripts/gerar_hash_senha.py
"""

from getpass import getpass

from werkzeug.security import generate_password_hash


def main() -> None:
    senha = getpass("Senha do admin: ")
    if not senha or senha != getpass("Confirme a senha: "):
        raise SystemExit("As senhas não conferem.")
    print(generate_password_hash(senha))


if __name__ == "__main__":
    main()
