"""Exceções de domínio, traduzidas em respostas HTTP pelo app.

Os módulos de negócio não conhecem o Flask: sinalizam o problema com
uma destas exceções e o handler registrado em ``app.py`` decide o
status e o corpo da resposta, sem vazar detalhes internos.
"""


class ErroAplicacao(Exception):
    """Base de todos os erros esperados da aplicação."""

    status_http = 500


class ErroValidacao(ErroAplicacao):
    """Entrada do cliente fora do formato ou da política permitida."""

    status_http = 400


class RecursoNaoEncontrado(ErroAplicacao):
    """O recurso solicitado não existe."""

    status_http = 404


class RecursoIndisponivel(ErroAplicacao):
    """Dependência externa (processo, serviço) falhou ou não respondeu."""

    status_http = 503
