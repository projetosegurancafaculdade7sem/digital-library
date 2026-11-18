#!/usr/bin/env bash
# Imprime e executa comandos de evidência de segurança. Nunca imprime valores de segredos.
set -uo pipefail

SECTION="all"
URL="https://localhost:8443"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --section)
      SECTION="${2:-all}"
      shift 2
      ;;
    --url)
      URL="${2:-$URL}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Uso: capture-security-evidence.sh [--section all|tests|sast|sca|secrets|tls|dast] [--url URL]
Imprime e executa comandos de evidência. Nunca imprime valores de segredos.
USAGE
      exit 0
      ;;
    *)
      echo "Opção desconhecida: $1" >&2
      exit 2
      ;;
  esac
done

header() {
  printf '\n===== %s =====\n' "$1"
}

show_cmd() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
}

run_if() {
  local tool="$1"
  shift
  if command -v "$tool" >/dev/null 2>&1 || [[ -x "$tool" ]]; then
    show_cmd "$tool" "$@"
    "$tool" "$@" 2>&1
    local status=$?
    if [[ $status -ne 0 ]]; then
      printf '[WARN] comando terminou com status %s\n' "$status"
    fi
    return 0
  fi
  show_cmd "$tool" "$@"
  printf '[SKIP] ferramenta não disponível: %s\n' "$tool"
}

run_shell_if() {
  local tool="$1"
  shift
  if command -v "$tool" >/dev/null 2>&1; then
    printf '$ %s\n' "$*"
    "$@" 2>&1
    local status=$?
    if [[ $status -ne 0 ]]; then
      printf '[WARN] comando terminou com status %s\n' "$status"
    fi
  else
    printf '[SKIP] ferramenta não disponível: %s\n' "$tool"
  fi
}

section_tests() {
  header "Testes automatizados (H2, sem banco real)"
  if [[ -x ./mvnw ]]; then
    run_if ./mvnw -B clean test
  elif command -v mvn >/dev/null 2>&1; then
    run_if mvn -B clean test
  else
    show_cmd ./mvnw -B clean test
    printf '[SKIP] Maven wrapper não encontrado\n'
  fi
}

section_sast() {
  header "SAST - Semgrep"
  run_if docker run --rm -v "$PWD:/src" -w /src returntocorp/semgrep:latest \
    semgrep --config p/java --config p/spring-boot --config p/security-audit .
}

section_sca() {
  header "SCA - Trivy"
  run_if docker run --rm -v "$PWD:/src" -w /src aquasec/trivy:0.76.1 \
    fs --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed .
}

section_secrets() {
  header "Segredos - TruffleHog (histórico completo)"
  run_if docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
    git file:///repo --only-verified --results=verified,unknown --json

  header "Privacidade - Bearer"
  run_if docker run --rm -v "$PWD:/repo" -w /repo bearer/bearer:latest scan . --format yaml
}

section_tls() {
  header "TLS - certificado, protocolo e HSTS"
  if [[ -x ./scripts/verify-tls.sh ]]; then
    run_if ./scripts/verify-tls.sh "$URL"
  else
    show_cmd ./scripts/verify-tls.sh "$URL"
    printf '[SKIP] scripts/verify-tls.sh não encontrado\n'
  fi
}

section_dast() {
  header "DAST - checagem HTTP do alvo"
  run_shell_if curl curl -sS -D - -o /dev/null "$URL"
  printf '\nComando ZAP equivalente (fora deste script):\n'
  printf '$ docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t %s -I -j\n' "$URL"
}

case "$SECTION" in
  all)
    section_tests
    section_sast
    section_sca
    section_secrets
    section_tls
    section_dast
    ;;
  tests) section_tests ;;
  sast) section_sast ;;
  sca) section_sca ;;
  secrets) section_secrets ;;
  tls) section_tls ;;
  dast) section_dast ;;
  *)
    echo "Seção desconhecida: $SECTION (use all|tests|sast|sca|secrets|tls|dast)" >&2
    exit 2
    ;;
esac
