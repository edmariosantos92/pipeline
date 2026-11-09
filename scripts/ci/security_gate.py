"""Portão de segurança da esteira: decide se relatórios SARIF bloqueiam o build.

Todos os scanners da esteira (Gitleaks, Semgrep, Trivy, Hadolint, ZAP)
emitem SARIF; este script aplica a mesma política a todos eles, publica
um resumo no job do GitHub Actions e anota cada achado bloqueante.

Falha fechada: relatório ausente ou inválido também bloqueia (exit 2).

Uso:
    python scripts/ci/security_gate.py --nome "SAST (Semgrep)" \\
        --bloquear-em error relatorios/semgrep.sarif
"""

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

NIVEIS = ("error", "warning", "note", "none")
NIVEL_PADRAO = "warning"  # SARIF 2.1.0, seção 3.27.10
MAXIMO_NO_RESUMO = 25

APROVADO, BLOQUEADO, RELATORIO_INVALIDO = 0, 1, 2


@dataclass(frozen=True)
class Achado:
    regra: str
    nivel: str
    arquivo: str
    linha: int | None
    mensagem: str

    @property
    def local(self) -> str:
        return f"{self.arquivo}:{self.linha}" if self.linha else self.arquivo


def ler_achados(caminho: Path) -> list[Achado]:
    """Extrai os achados de um arquivo SARIF, resolvendo o nível efetivo."""
    sarif = json.loads(caminho.read_text(encoding="utf-8"))
    achados = []
    for execucao in sarif.get("runs", []):
        niveis_das_regras = _niveis_padrao_das_regras(execucao)
        for resultado in execucao.get("results") or []:
            regra = resultado.get("ruleId", "desconhecida")
            nivel = resultado.get("level") or niveis_das_regras.get(regra, NIVEL_PADRAO)
            arquivo, linha = _localizacao(resultado)
            mensagem = resultado.get("message", {}).get("text", "")
            achados.append(Achado(regra, nivel, arquivo, linha, mensagem))
    return achados


def filtrar_bloqueantes(achados: Iterable[Achado], niveis_bloqueantes: set[str]) -> list[Achado]:
    return [achado for achado in achados if achado.nivel in niveis_bloqueantes]


def montar_resumo(nome: str, achados: list[Achado], bloqueantes: list[Achado], niveis: set[str]) -> str:
    """Gera o resumo em Markdown exibido na página da execução."""
    contagem = Counter(achado.nivel for achado in achados)
    status = "❌ bloqueado" if bloqueantes else "✅ aprovado"
    politica = ", ".join(nivel for nivel in NIVEIS if nivel in niveis)
    linhas = [
        f"### {nome}: {status}",
        "",
        f"Política do portão: bloqueia em `{politica}`.",
        "",
        "| Nível | Achados |",
        "|---|---|",
        *(f"| {nivel} | {contagem.get(nivel, 0)} |" for nivel in NIVEIS),
    ]
    if bloqueantes:
        linhas += ["", "| Regra | Local | Mensagem |", "|---|---|---|"]
        linhas += [
            f"| `{achado.regra}` | `{achado.local}` | {_texto_de_celula(achado.mensagem)} |"
            for achado in bloqueantes[:MAXIMO_NO_RESUMO]
        ]
        if len(bloqueantes) > MAXIMO_NO_RESUMO:
            linhas += ["", f"… e mais {len(bloqueantes) - MAXIMO_NO_RESUMO} no relatório completo (artefato do job)."]
    return "\n".join(linhas) + "\n"


def main(argv: list[str] | None = None) -> int:
    argumentos = _ler_argumentos(argv)
    try:
        achados = [achado for caminho in argumentos.relatorios for achado in ler_achados(caminho)]
    except (OSError, ValueError, AttributeError) as erro:
        print(f"::error title={argumentos.nome}::Relatório ausente ou inválido: {erro}")
        return RELATORIO_INVALIDO

    bloqueantes = filtrar_bloqueantes(achados, argumentos.bloquear_em)
    resumo = montar_resumo(argumentos.nome, achados, bloqueantes, argumentos.bloquear_em)
    print(resumo)
    _publicar_resumo_do_job(resumo)
    for achado in bloqueantes:
        print(_anotacao_github(argumentos.nome, achado))
    return BLOQUEADO if bloqueantes else APROVADO


def _niveis_padrao_das_regras(execucao: dict) -> dict[str, str]:
    regras = execucao.get("tool", {}).get("driver", {}).get("rules") or []
    return {
        regra["id"]: regra["defaultConfiguration"]["level"]
        for regra in regras
        if regra.get("defaultConfiguration", {}).get("level")
    }


def _localizacao(resultado: dict) -> tuple[str, int | None]:
    locais = resultado.get("locations") or [{}]
    fisica = locais[0].get("physicalLocation", {})
    arquivo = fisica.get("artifactLocation", {}).get("uri", "-")
    linha = fisica.get("region", {}).get("startLine")
    return arquivo, linha


def _texto_de_celula(texto: str, limite: int = 160) -> str:
    uma_linha = " ".join(texto.split()).replace("|", "\\|")
    return uma_linha if len(uma_linha) <= limite else uma_linha[: limite - 1] + "…"


def _anotacao_github(nome: str, achado: Achado) -> str:
    posicao = f"file={achado.arquivo},line={achado.linha}," if achado.linha else ""
    return f"::error {posicao}title={nome}::[{achado.regra}] {_texto_de_celula(achado.mensagem)}"


def _publicar_resumo_do_job(resumo: str) -> None:
    destino = os.getenv("GITHUB_STEP_SUMMARY")
    if destino:
        with open(destino, "a", encoding="utf-8") as arquivo:
            arquivo.write(resumo + "\n")


def _niveis(valor: str) -> set[str]:
    niveis = {nivel.strip() for nivel in valor.split(",") if nivel.strip()}
    invalidos = niveis - set(NIVEIS)
    if not niveis or invalidos:
        raise argparse.ArgumentTypeError(f"níveis inválidos: {sorted(invalidos) or valor!r}; use {NIVEIS}")
    return niveis


def _ler_argumentos(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--nome", required=True, help="Nome da estação exibido no resumo")
    parser.add_argument(
        "--bloquear-em", type=_niveis, default={"error"}, help="Níveis SARIF que bloqueiam, separados por vírgula"
    )
    parser.add_argument("relatorios", nargs="+", type=Path, help="Arquivos SARIF")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # emojis do resumo em qualquer console
    sys.exit(main())
