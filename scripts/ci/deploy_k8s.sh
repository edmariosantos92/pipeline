#!/usr/bin/env bash
# Implanta o Simulador de Cartões no Kubernetes (Estação 8 da esteira).
#
# Variáveis esperadas:
#   KUBE_CONFIG          kubeconfig do cluster, em base64
#   IMAGEM_REPOSITORIO   ex.: ghcr.io/dono/repositorio
#   IMAGEM_DIGEST        digest aprovado e assinado (sha256:...)
#   SECRET_KEY, ADMIN_PASSWORD_HASH, DB_PASSWORD, API_KEY_BANDEIRA
set -euo pipefail

readonly NAMESPACE=cartoes
readonly IMAGEM="${IMAGEM_REPOSITORIO}@${IMAGEM_DIGEST}"

: "${KUBE_CONFIG:?secret KUBE_CONFIG não configurado no Environment producao}"
: "${SECRET_KEY:?secret SECRET_KEY não configurado no Environment producao}"

configurar_acesso_ao_cluster() {
  export KUBECONFIG="${RUNNER_TEMP:-/tmp}/kubeconfig"
  base64 --decode <<< "$KUBE_CONFIG" > "$KUBECONFIG"
  chmod 600 "$KUBECONFIG"
}

verificar_assinatura() {
  # Só implanta imagem assinada por esta mesma esteira, neste repositório.
  cosign verify "$IMAGEM" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/" > /dev/null
}

aplicar_controles_do_namespace() {
  # Namespace com Pod Security "restricted", RBAC mínimo e NetworkPolicies.
  kubectl apply -f k8s/08-namespace-pod-security.yaml
  kubectl apply -f k8s/02-rbac-corrigido.yaml \
                -f k8s/03-networkpolicy-default-deny.yaml \
                -f k8s/04-networkpolicy-allow-dns.yaml \
                -f k8s/05-networkpolicy-allow-gateway.yaml
}

aplicar_secret() {
  # Os valores vêm dos GitHub Secrets; nunca são gravados no repositório.
  kubectl create secret generic simulador-cartoes-secret \
    --namespace "$NAMESPACE" \
    --from-literal=SECRET_KEY="$SECRET_KEY" \
    --from-literal=ADMIN_PASSWORD_HASH="${ADMIN_PASSWORD_HASH:-}" \
    --from-literal=DB_PASSWORD="${DB_PASSWORD:-}" \
    --from-literal=API_KEY_BANDEIRA="${API_KEY_BANDEIRA:-}" \
    --dry-run=client --output yaml | kubectl apply -f -
}

implantar_aplicacao() {
  # shellcheck disable=SC2016 # envsubst recebe os NOMES das variáveis, sem expansão
  envsubst '${IMAGEM_REPOSITORIO} ${IMAGEM_DIGEST}' < k8s/07-deployment-hardened.yaml | kubectl apply -f -
  kubectl rollout status deployment/simulador-cartoes --namespace "$NAMESPACE" --timeout=180s
}

main() {
  configurar_acesso_ao_cluster
  verificar_assinatura
  aplicar_controles_do_namespace
  aplicar_secret
  implantar_aplicacao
  echo "### Implantado em produção: \`$IMAGEM\`" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

main "$@"
