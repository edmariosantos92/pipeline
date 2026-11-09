# Simulador de Cartões de Crédito — Esteira DevSecOps

API Flask de treinamento em desenvolvimento seguro. A versão original
continha **12 vulnerabilidades plantadas** na aplicação e **9 nos manifests
Kubernetes**; todas foram corrigidas e cada correção é protegida por um
teste de regressão e por uma esteira DevSecOps de 8 estações.

## Esteira DevSecOps (`.github/workflows/esteira-devsecops.yml`)

```
1 Segredos ─► 2 SAST ─► 3 Build ─► 4 SCA/IaC ─► 5 Package ─► 6 Scan imagem ─► 7 Homolog + DAST ─► 8 Aprovação + Produção
```

| # | Estação | Ferramenta | Bloqueia quando |
|---|---------|------------|-----------------|
| 1 | Segredos | Gitleaks (histórico completo) | qualquer segredo novo |
| 2 | SAST | Semgrep: OWASP Top 10, Python, Flask, secrets + `regras-banco/` | achado de severidade ERROR |
| 3 | Build | Ruff (lint e formatação) + pytest | lint ou teste falhando |
| 4 | SCA e IaC | Trivy (dependências, Dockerfile, k8s) + Hadolint | CVE CRITICAL/HIGH com correção; má configuração HIGH+ |
| 5 | Package | Docker Buildx + SBOM CycloneDX | falha de build |
| 6 | Scan da imagem | Trivy (SO, pacotes, segredos nas camadas) | CVE CRITICAL/HIGH com correção |
| 7 | Homologação + DAST | OWASP ZAP, scan **ativo** sobre todas as rotas | alerta de risco ALTO |
| 8 | Aprovação + Produção | Environment `producao`, GHCR, Cosign, kubectl | revisor rejeita, assinatura inválida ou rollout falha |

Princípios do desenho:

- **Uma imagem, um caminho.** A imagem é construída uma vez (estação 5) e o
  mesmo artefato passa pelas estações 6, 7 e 8. Nada vai para o registry
  antes da aprovação humana, e o deploy usa o **digest**, não uma tag.
- **Um portão para todos.** Todo scanner gera SARIF, e uma única política
  (`scripts/ci/security_gate.py`, com testes) decide se o build passa,
  publica o resumo no job e anota os achados no código. O portão **falha
  fechado**: se o relatório estiver ausente ou inválido, o build é bloqueado.
- **Cadeia de suprimentos.** As actions são fixadas por SHA de commit e as
  ferramentas por versão + digest. As permissões do `GITHUB_TOKEN` são
  mínimas e definidas por job. A imagem é assinada sem chave (Sigstore) e
  leva o SBOM atestado. O Dependabot mantém tudo atualizado.
- **Vigilância contínua.** `scan-agendado.yml` repete diariamente as
  varreduras de segredos, dependências e da imagem em produção.

### Configuração no GitHub

| Item | Onde | Uso |
|------|------|-----|
| Environment `producao` com *Required reviewers* | Settings → Environments | aprovação humana da estação 8 |
| Environment `homologacao` | Settings → Environments | estação 7 |
| Variável `KUBE_DEPLOY=true` | Environment `producao` | habilita o deploy no cluster (sem ela, a estação 8 publica e assina a imagem) |
| Secrets `KUBE_CONFIG` (kubeconfig em base64), `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `DB_PASSWORD`, `API_KEY_BANDEIRA` | Environment `producao` | deploy e Secret do Kubernetes |

O cluster precisa conseguir baixar a imagem do GHCR: torne o pacote público
ou configure um `imagePullSecret`.

## Executando localmente

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check . && pytest

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_PASSWORD_HASH="$(python scripts/gerar_hash_senha.py)"
python app.py                      # desenvolvimento (127.0.0.1:5000)

docker build -t simulador-cartoes . # produção: Gunicorn, usuário 10001
docker run --rm -p 5000:5000 -e SECRET_KEY="$SECRET_KEY" simulador-cartoes
```

Variáveis de ambiente opcionais: `FLASK_DEBUG`, `DB_PATH`, `EXTRATOS_DIR`,
`GERADOR_RELATORIO` e `WEBHOOK_HOSTS_PERMITIDOS` (hosts separados por vírgula).

## Vulnerabilidades da aplicação: o que foi corrigido

| # | Arquivo | Vulnerabilidade original | Correção |
|---|---------|---------------------------|----------|
| 1 | `config.py` | Segredos hardcoded | tudo vem do ambiente; `SECRET_KEY` é obrigatória (falha na subida) |
| 2 | `app.py` | `debug=True` | debug desligado por padrão; em contêiner roda no Gunicorn |
| 3 | `modulos/autenticacao.py` | Hash MD5 | scrypt com salt (Werkzeug); verificação em tempo constante |
| 4 | `modulos/autenticacao.py` | Token com `random` | `secrets.token_urlsafe(32)` |
| 5–6 | `modulos/cartoes.py` | SQL Injection | consultas parametrizadas, validação estrita, número do cartão mascarado |
| 7 | `modulos/relatorios.py` | Command Injection no relatório | allowlist de formatos, sem shell, executável fixo, timeout |
| 8 | `modulos/relatorios.py` | Path Traversal | `safe_join` restrito ao diretório de extratos |
| 9 | `modulos/relatorios.py` | Execução de comando arbitrário | só verificações internas pré-definidas |
| 10 | `modulos/notificacoes.py` | SSRF | só HTTPS, porta 443, allowlist de hosts, sem redirects |
| 11 | `modulos/notificacoes.py` | `pickle.loads` | JSON com validação de tipo e tamanho |
| 12 | `modulos/credito.py` | `eval()` | avaliador aritmético restrito sobre a AST |

Controles transversais: cabeçalhos de segurança (CSP, `nosniff`, `X-Frame-Options`...)
em toda resposta e erros em JSON padronizado, sem stack trace para o cliente.
Os testes ficam em `tests/test_correcoes_vulnerabilidades.py`, um bloco por item.

## Kubernetes

| # | Vulnerabilidade em `k8s/01-vulneravel.yaml` | Corrigida em |
|---|----------------------------------------------|--------------|
| 1 | ClusterRoleBinding de cluster-admin | `02-rbac-corrigido.yaml` |
| 2 | Segredo em ConfigMap | Secret criado pela esteira a partir dos GitHub Secrets |
| 3–5 | privileged, root, privilege escalation | `07-deployment-hardened.yaml` |
| 6 | Tag `latest` | `07` (imagem por digest, injetado pela esteira) |
| 7–8 | Sem resources e sem probes | `07-deployment-hardened.yaml` |
| 9 | Sem NetworkPolicy | `03`, `04` e `05-networkpolicy-*.yaml` |

`08-namespace-pod-security.yaml` aplica Pod Security **restricted**, então o
próprio API Server rejeita pods inseguros. Para conferir, aplique a baseline
`01` num cluster de laboratório e veja a rejeição.

> `k8s/01-vulneravel.yaml` continua no repositório **apenas como material
> didático** (o "antes"). A esteira nunca o implanta, e ele fica fora das
> varreduras de SAST e IaC de forma explícita (`.semgrepignore` e `--skip-files`).
> Se o laboratório já criou o ClusterRoleBinding vulnerável, remova-o:
> `kubectl delete clusterrolebinding simulador-cartoes-binding`.

## Segredos no histórico

Versões antigas deste repositório tinham segredos fictícios commitados
(`config.py`, manifests e um `leaks.json`). Eles saíram do código e estão
registrados no baseline `.gitleaksignore`, então a estação 1 continua
varrendo **todo** o histórico e bloqueia qualquer segredo novo. Em um cenário
real, esses valores seriam considerados comprometidos e **rotacionados**.

## Estrutura

```
├── app.py, config.py           # API Flask e configuração por ambiente
├── modulos/                    # regras de negócio (sem dependência do Flask)
├── tests/                      # contrato HTTP, regressões de segurança, portão
├── scripts/
│   ├── gerar_hash_senha.py     # gera ADMIN_PASSWORD_HASH
│   └── ci/                     # portão SARIF e deploy no Kubernetes
├── regras-banco/               # regras customizadas do Semgrep
├── k8s/                        # baseline didática (01) e manifests corrigidos
├── .zap/automation.yaml        # plano do DAST (OWASP ZAP)
└── .github/                    # esteira, scan agendado, Dependabot, action do portão
```
