# syntax=docker/dockerfile:1
#
# Imagem do Simulador de Cartões de Crédito.
# - Base fixada por digest (atualizada via Dependabot);
# - Patches de segurança do SO aplicados no build;
# - Sem compilador e sem pip na imagem final (menor superfície de ataque);
# - Código pertencente ao root e somente leitura para o processo;
# - Usuário não-root com UID numérico (exigido por runAsNonRoot no Kubernetes);
# - Servidor WSGI de produção (Gunicorn) em vez do servidor de desenvolvimento.

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-compile -r requirements.txt \
    && pip uninstall -y pip

COPY app.py config.py ./
COPY modulos/ ./modulos/

USER 10001:10001

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/saude', timeout=2)"]

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "app:app"]
