# Documentação de Segurança — Digital Library
# Atende requisitos 1.2, 1.7, 1.9, 1.12, 3.1–3.8, 4.11, 5.3–5.4

## 1. Fluxo de autenticação (req. 1.7)

```
[HTTPS] Cliente
   │
   ▼
GET /login
   │
   ▼
POST /perform_login  ← RateLimitingFilter (10 req/min/IP)
   │
   ├─ falha → LoginAuthenticationFailureHandler
   │            └─ AuthService.registerFailedPasswordAttempt
   │                 (após 5 falhas: bloqueio 15 min + log ACCOUNT_LOCKED_*)
   │
   └─ sucesso → LoginAuthenticationSuccessHandler
                  ├─ log LOGIN_PRIMARY_SUCCESS
                  └─ redirect /login-2fa
                       │
                       ▼
                 POST /login-2fa (código TOTP do autenticador)
                       │
                       ├─ inválido → AuthService.registerFailed2FAAttempt + log LOGIN_FAILED_2FA
                       └─ válido → sessão 2FA_VERIFIED=true + log LOGIN_SUCCESS_2FA
                                    └─ /dashboard
```

Logout (`POST /logout`): invalida sessão HTTP e remove cookie `JSESSIONID` (req. 1.10).

Implementação canônica de TOTP: `TwoFactorService` (TotpManager é apenas fachada).

## 2. Hash de senha Argon2id (req. 1.1 / 1.2 / 1.3 / 1.4 / 1.12)

| Parâmetro   | Valor  | Justificativa |
|------------|--------|---------------|
| saltLength | 16     | 128 bits de entropia; unicidade por senha (OWASP / RFC 9106) |
| hashLength | 32     | 256 bits de digest armazenado |
| parallelism| 1      | Adequado a host acadêmico single-node |
| memory     | 65536  | 64 MiB — eleva custo em GPU/ASIC |
| iterations | 3      | Passes recomendados com ~64 MiB (Argon2id) |

O `Argon2PasswordEncoder` gera salt interno a cada `encode()` e o embute na string PHC.
`PasswordHashingSupport` extrai esse salt e grava em `User.passwordSalt`, atendendo ao
armazenamento explícito hash + salt sem reinventar o KDF.

## 3. Sessões (req. 1.9)

- `SessionCreationPolicy.IF_REQUIRED`
- `maximumSessions(1)`
- `server.servlet.session.timeout=15m` (expiração por inatividade)

## 4. Comunicação TLS/HTTPS (req. 3.1 / 3.2 / 3.3)

- Keystore PKCS12 (`classpath:keystore.p12`), porta 8443
- Conector HTTP 8080 redireciona para HTTPS
- `http.redirectToHttps(Customizer.withDefaults())` quando SSL está habilitado (API do Spring Security 7; substitui `requiresChannel`)
- Evidência: acessar `https://localhost:8443` e inspecionar certificado / DevTools (cadeado)

SMTP Mailtrap com STARTTLS protege o e-mail, mas **não** substitui HTTPS da aplicação.

## 5. Criptografia em repouso (req. 3.4–3.8)

- Classe: `AttributeEncryptor`
- Algoritmo: **AES-256-GCM** (AEAD) — confidencialidade + tag de autenticação
- IV: 12 bytes aleatórios (NIST SP 800-38D) por valor
- Campo protegido: `User.twoFactorSecret` (`@Convert`)
- Chave: 32 bytes em Base64 via `security.encryption.key-base64` / env `SECURITY_ENCRYPTION_KEY_BASE64`
  (não hardcoded no código-fonte)

## 6. Proteção contra força bruta (req. 1.11)

1. `RateLimitingFilter` (Bucket4j): 10 req/min nas rotas `/perform_login`, `/login`, `/login-2fa`,
   `/register`, `/forgot-password`, `/reset-password`
2. Bloqueio de conta após 5 falhas (senha ou 2FA), por 15 minutos — integrado ao `formLogin`

## 7. Fluxo LGPD — direitos do titular (req. 4.4 / 4.6–4.11)

| Direito | Endpoint | Descrição |
|---------|----------|-----------|
| Consentimento no cadastro | `POST /register` + `acceptTerms` | Grava `UserConsent` (versão + finalidade) |
| Consulta | `GET /privacy/my-data` | Dados pessoais do titular |
| Exportação | `GET /privacy/export` | JSON download |
| Histórico | `GET /privacy/consents` | Consentimentos ordenados por data |
| Revogação | `POST /privacy/consent/revoke` | `granted=false` + auditoria |
| Exclusão | `POST /privacy/delete` | Anonimização + log |

Eventos auditados: `LGPD_CONSENT_GRANTED_*`, `LGPD_CONSENT_REVOKED_*`, `LGPD_DATA_EXPORT`, `LGPD_DATA_DELETED`.

## 8. Auditoria (req. 5.1–5.4)

- Cadeia hash SHA-256 (`previousHash` → `logHash`), campos imutáveis (`updatable=false`)
- Logs de autenticação: `LOGIN_PRIMARY_SUCCESS`, `LOGIN_SUCCESS_2FA`, `LOGIN_FAILED_*`, `ACCOUNT_LOCKED_*`
- Análise: `GET /admin/audit/analyze` (e `.json`) — contagens, amostra recente e `integrityChainValid`

## 9. Referências técnicas

- RFC 9106 — Argon2
- OWASP Password Storage Cheat Sheet
- NIST SP 800-38D — GCM
- RFC 6238 — TOTP
- Lei nº 13.709/2018 (LGPD)
