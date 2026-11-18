#!/usr/bin/env bash
# Valida TLS/certificado/HSTS do ambiente publicado. Uso:
#   verify-tls.sh https://host:8443 [ca.pem]
#   verify-tls.sh host 8443 [ca.pem]
set -uo pipefail

show_cmd() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
}

if [[ $# -lt 1 ]]; then
  echo "Uso: $0 https://host:8443 [ca.pem]  |  $0 host 8443 [ca.pem]" >&2
  exit 2
fi

CA_FILE=""
if [[ "$1" == *"://"* ]]; then
  AUTHORITY="${1#*://}"
  AUTHORITY="${AUTHORITY%%/*}"
  HOST="${AUTHORITY%%:*}"
  PORT="${AUTHORITY##*:}"
  [[ "$PORT" == "$AUTHORITY" ]] && PORT=443
  CA_FILE="${2:-}"
else
  HOST="$1"
  PORT="${2:-443}"
  CA_FILE="${3:-}"
fi

if [[ -z "$HOST" || -z "$PORT" ]]; then
  echo "Host/porta inválidos" >&2
  exit 2
fi

URL="https://${HOST}:${PORT}/"
TARGET="${HOST}:${PORT}"
RESULT=0

printf '===== TLS %s =====\n' "$TARGET"

CURL_CA_ARGS=()
if [[ -n "$CA_FILE" ]]; then
  CURL_CA_ARGS=(--cacert "$CA_FILE")
fi

printf '\n-- Handshake e certificado --\n'
show_cmd openssl s_client -connect "$TARGET" -servername "$HOST" -showcerts '</dev/null'
S_CLIENT_OUT="$(openssl s_client -connect "$TARGET" -servername "$HOST" -showcerts </dev/null 2>/dev/null)"
if [[ -z "$S_CLIENT_OUT" ]]; then
  echo '[FAIL] Não foi possível estabelecer handshake TLS'
  exit 1
fi

printf '%s\n' "$S_CLIENT_OUT" | openssl x509 -noout -subject -issuer -dates 2>/dev/null || true
printf '%s\n' "$S_CLIENT_OUT" | openssl x509 -noout -ext subjectAltName 2>/dev/null || true
printf '%s\n' "$S_CLIENT_OUT" | grep -m1 -E '^(New|Protocol)' || true

printf '\n-- Validade do certificado --\n'
show_cmd openssl s_client -connect "$TARGET" -servername "$HOST" '</dev/null' | openssl x509 -noout -checkend 0
if printf '%s\n' "$S_CLIENT_OUT" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
  echo '[OK] Certificado válido'
else
  echo '[FAIL] Certificado expirado ou inválido'
  RESULT=1
fi

printf '\n-- Versão do protocolo (obrigatório TLSv1.2+) --\n'
PROTOCOL_LINE="$(printf '%s\n' "$S_CLIENT_OUT" | grep -m1 -E 'Protocol *: *TLSv' || true)"
echo "$PROTOCOL_LINE"
if [[ "$PROTOCOL_LINE" =~ TLSv(1\.[23]|1\.3) ]]; then
  echo '[OK] Protocolo satisfatório'
else
  echo '[WARN] Não foi possível confirmar TLS >= 1.2; revise a configuração do servidor'
fi

printf '\n-- Cadeia confiável (curl) --\n'
show_cmd curl -Iv "${CURL_CA_ARGS[@]}" "$URL"
if curl -Iv --max-time 15 "${CURL_CA_ARGS[@]}" "$URL" >/dev/null 2>&1; then
  echo '[OK] Cadeia validada pelo cliente'
else
  echo '[FAIL] curl não validou a cadeia; verifique CA, SNI e certificado intermediate'
  RESULT=1
fi

printf '\n-- HSTS --\n'
show_cmd curl -sI "${CURL_CA_ARGS[@]}" "$URL" '| grep -i strict-transport-security'
if curl -sI --max-time 15 "${CURL_CA_ARGS[@]}" "$URL" | grep -i '^strict-transport-security:'; then
  echo '[OK] HSTS presente'
else
  echo '[WARN] HSTS ausente na resposta; confirme o cabeçalho no proxy/ingress'
fi

exit "$RESULT"
