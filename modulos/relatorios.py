"""Relatórios, extratos e diagnóstico operacional.

Nenhuma entrada do cliente chega a um shell: o gerador de relatórios é
chamado com argumentos em lista e formato de uma allowlist; extratos
só são lidos de dentro do diretório configurado; e o diagnóstico
executa apenas verificações internas pré-definidas.
"""

import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from werkzeug.utils import safe_join

import config
from modulos.erros import ErroValidacao, RecursoIndisponivel, RecursoNaoEncontrado

FORMATOS_RELATORIO = frozenset({"pdf", "csv"})
TEMPO_LIMITE_RELATORIO_SEGUNDOS = 30

_INICIO_PROCESSO = time.monotonic()

VERIFICACOES_DIAGNOSTICO = {
    "horario-utc": lambda: datetime.now(UTC).isoformat(),
    "tempo-atividade": lambda: f"{time.monotonic() - _INICIO_PROCESSO:.0f}s",
}


def gerar_relatorio(formato: str | None) -> str:
    """Gera o relatório no formato pedido usando o gerador externo."""
    if formato not in FORMATOS_RELATORIO:
        raise ErroValidacao(f"formato inválido; use um de: {', '.join(sorted(FORMATOS_RELATORIO))}")
    try:
        resultado = subprocess.run(  # noqa: S603 - executável fixo, argumentos em lista
            [config.GERADOR_RELATORIO, formato],
            capture_output=True,
            text=True,
            check=True,
            timeout=TEMPO_LIMITE_RELATORIO_SEGUNDOS,
        )
    except (OSError, subprocess.SubprocessError) as erro:
        raise RecursoIndisponivel("gerador de relatórios indisponível") from erro
    return resultado.stdout


def baixar_extrato(nome_arquivo: str | None) -> str:
    """Lê um extrato, garantindo que o caminho não escape do diretório base."""
    caminho = safe_join(config.EXTRATOS_DIR, nome_arquivo) if nome_arquivo else None
    if caminho is None:
        raise ErroValidacao("nome de arquivo inválido")
    arquivo = Path(caminho)
    if not arquivo.is_file():
        raise RecursoNaoEncontrado("extrato não encontrado")
    return arquivo.read_text(encoding="utf-8")


def executar_diagnostico(verificacao: str | None) -> dict:
    """Executa uma verificação interna identificada pelo nome."""
    executar = VERIFICACOES_DIAGNOSTICO.get(verificacao or "")
    if executar is None:
        raise ErroValidacao(f"verificação inválida; use uma de: {', '.join(sorted(VERIFICACOES_DIAGNOSTICO))}")
    return {"verificacao": verificacao, "resultado": executar()}
