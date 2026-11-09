import os

import pytest

# config.py exige SECRET_KEY na importação; definimos antes de importar o app.
os.environ.setdefault("SECRET_KEY", "chave-somente-para-testes")

import config
from app import criar_app


@pytest.fixture
def cliente():
    return criar_app().test_client()


@pytest.fixture
def configuracao(monkeypatch):
    """Permite sobrescrever valores de config.py em um teste isolado."""

    def definir(**valores):
        for nome, valor in valores.items():
            monkeypatch.setattr(config, nome, valor)

    return definir
