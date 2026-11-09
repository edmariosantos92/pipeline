"""Simulador de Cartões de Crédito — API Flask.

As rotas só fazem a tradução HTTP: leem parâmetros, delegam aos módulos
de negócio e serializam a resposta. Erros de domínio viram respostas
JSON padronizadas e todas as respostas levam cabeçalhos de segurança.
"""

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

import config
from modulos import autenticacao, cartoes, credito, notificacoes, relatorios
from modulos.erros import ErroAplicacao, RecursoNaoEncontrado

CABECALHOS_SEGURANCA = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def criar_app() -> Flask:
    aplicacao = Flask(__name__)
    aplicacao.secret_key = config.SECRET_KEY
    _registrar_rotas(aplicacao)
    _registrar_tratamento_de_erros(aplicacao)
    aplicacao.after_request(_aplicar_cabecalhos_seguranca)
    return aplicacao


def _registrar_rotas(aplicacao: Flask) -> None:
    @aplicacao.get("/saude")
    def saude():
        """Health check usado pelas probes do Kubernetes."""
        return jsonify({"status": "ok"})

    @aplicacao.post("/login")
    def login():
        usuario = request.form.get("usuario")
        senha = request.form.get("senha")
        if not autenticacao.validar_login(usuario, senha):
            return jsonify({"erro": "credenciais inválidas"}), 401
        return jsonify({"token": autenticacao.gerar_token_sessao()})

    @aplicacao.get("/fatura")
    def fatura():
        resultado = cartoes.consultar_fatura(request.args.get("numero_cartao"))
        if resultado is None:
            raise RecursoNaoEncontrado("cartão não encontrado")
        return jsonify(resultado)

    @aplicacao.get("/cartoes")
    def listar_cartoes():
        return jsonify(cartoes.buscar_cartoes_cliente(request.args.get("cpf")))

    @aplicacao.get("/relatorio")
    def relatorio():
        conteudo = relatorios.gerar_relatorio(request.args.get("formato", "pdf"))
        return conteudo, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @aplicacao.get("/extrato")
    def extrato():
        conteudo = relatorios.baixar_extrato(request.args.get("arquivo"))
        return conteudo, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @aplicacao.get("/diagnostico")
    def diagnostico():
        return jsonify(relatorios.executar_diagnostico(request.args.get("verificacao")))

    @aplicacao.post("/webhook")
    def webhook():
        status = notificacoes.enviar_webhook(request.form.get("url"), request.form.get("payload"))
        return jsonify({"status_destino": status})

    @aplicacao.get("/preferencias")
    def preferencias():
        return jsonify(notificacoes.carregar_preferencias_notificacao(request.args.get("dados")))

    @aplicacao.get("/simular-limite")
    def simular_limite():
        limite = credito.calcular_limite_credito(request.args.get("expressao"))
        return jsonify({"limite_estimado": limite})


def _registrar_tratamento_de_erros(aplicacao: Flask) -> None:
    @aplicacao.errorhandler(ErroAplicacao)
    def erro_de_dominio(erro: ErroAplicacao):
        return jsonify({"erro": str(erro)}), erro.status_http

    @aplicacao.errorhandler(HTTPException)
    def erro_http(erro: HTTPException):
        return jsonify({"erro": erro.name}), erro.code

    @aplicacao.errorhandler(Exception)
    def erro_inesperado(erro: Exception):
        # Detalhes vão para o log do servidor, nunca para o cliente.
        aplicacao.logger.exception("Erro não tratado", exc_info=erro)
        return jsonify({"erro": "erro interno"}), 500


def _aplicar_cabecalhos_seguranca(resposta):
    resposta.headers.update(CABECALHOS_SEGURANCA)
    return resposta


app = criar_app()

if __name__ == "__main__":
    # Apenas desenvolvimento local; em contêiner a aplicação roda no Gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=config.DEBUG)
