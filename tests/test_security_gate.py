"""Testes do portão de segurança que avalia os relatórios SARIF da esteira."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "ci"))

import security_gate as gate


def escrever_sarif(caminho: Path, resultados: list[dict], regras: list[dict] | None = None) -> Path:
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "scanner", "rules": regras or []}}, "results": resultados}],
    }
    caminho.write_text(json.dumps(sarif), encoding="utf-8")
    return caminho


def resultado(regra: str, nivel: str | None = None, arquivo: str = "app.py", linha: int = 10) -> dict:
    item = {
        "ruleId": regra,
        "message": {"text": f"achado {regra}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": arquivo}, "region": {"startLine": linha}}}],
    }
    if nivel:
        item["level"] = nivel
    return item


def test_relatorio_sem_achados_aprova(tmp_path):
    relatorio = escrever_sarif(tmp_path / "vazio.sarif", [])

    assert gate.main(["--nome", "SAST", str(relatorio)]) == gate.APROVADO


def test_achado_no_nivel_bloqueante_bloqueia(tmp_path, capsys):
    relatorio = escrever_sarif(tmp_path / "r.sarif", [resultado("sqli", "error", "modulos/cartoes.py", 21)])

    assert gate.main(["--nome", "SAST", str(relatorio)]) == gate.BLOQUEADO
    assert "::error file=modulos/cartoes.py,line=21,title=SAST::[sqli]" in capsys.readouterr().out


def test_achado_abaixo_da_politica_apenas_informa(tmp_path):
    relatorio = escrever_sarif(tmp_path / "r.sarif", [resultado("estilo", "note")])

    assert gate.main(["--nome", "SAST", "--bloquear-em", "error", str(relatorio)]) == gate.APROVADO


def test_nivel_ausente_herda_padrao_da_regra(tmp_path):
    regras = [{"id": "critica", "defaultConfiguration": {"level": "error"}}]
    relatorio = escrever_sarif(tmp_path / "r.sarif", [resultado("critica")], regras)

    assert gate.ler_achados(relatorio)[0].nivel == "error"


def test_nivel_ausente_sem_regra_assume_warning(tmp_path):
    relatorio = escrever_sarif(tmp_path / "r.sarif", [resultado("segredo")])

    assert gate.ler_achados(relatorio)[0].nivel == "warning"


def test_varios_relatorios_sao_avaliados_juntos(tmp_path):
    limpo = escrever_sarif(tmp_path / "a.sarif", [])
    sujo = escrever_sarif(tmp_path / "b.sarif", [resultado("cve", "error")])

    assert gate.main(["--nome", "SCA", str(limpo), str(sujo)]) == gate.BLOQUEADO


@pytest.mark.parametrize("conteudo", [None, "isto não é json", "[]"])
def test_relatorio_ausente_ou_invalido_falha_fechado(tmp_path, conteudo):
    relatorio = tmp_path / "r.sarif"
    if conteudo is not None:
        relatorio.write_text(conteudo, encoding="utf-8")

    assert gate.main(["--nome", "DAST", str(relatorio)]) == gate.RELATORIO_INVALIDO


def test_resumo_e_publicado_no_job(tmp_path, monkeypatch):
    resumo = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(resumo))
    relatorio = escrever_sarif(tmp_path / "r.sarif", [resultado("x", "error")])

    gate.main(["--nome", "Segredos", str(relatorio)])

    conteudo = resumo.read_text(encoding="utf-8")
    assert "### Segredos: ❌ bloqueado" in conteudo
    assert "| error | 1 |" in conteudo


def test_mensagem_com_barra_vertical_nao_quebra_a_tabela():
    assert gate._texto_de_celula("a | b\nc") == "a \\| b c"


def test_nivel_invalido_e_rejeitado_na_linha_de_comando(tmp_path):
    with pytest.raises(SystemExit):
        gate.main(["--nome", "X", "--bloquear-em", "critico", str(tmp_path / "r.sarif")])
