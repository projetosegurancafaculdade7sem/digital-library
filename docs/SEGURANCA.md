# Documentação de Segurança — Digital Library

Este documento descreve o estado **implementado no código**, em conformidade com o parecer conclusivo.
Os controles abaixo são verificados por testes automatizados, pela validação de inicialização e pelos
comandos reproduzíveis em [`TESTES.md`](TESTES.md).

## 1. Visão geral dos controles

| Frente do parecer | Controle implementado | Evidência |
|---|---|---|
| Autenticação e 2FA | Segundo fator exigido por filtro central antes da autorização; código TOTP de uso único (anti-replay) | `TwoFactorEnforcementFilter`, `AuthenticationEnforcementTest`, `TotpReplayTest`, [`sql/totp-replay.sql`](sql/totp-replay.sql) |
| Recuperação de senha | Token HMAC, 15 min, uso único atômico, política, anti-enumeração | `PasswordResetService`, `PasswordResetServiceTest` |
| Criptografia/TLS | TLS obrigatório via ENV, AES-256-GCM e HMAC-SHA256 com chaves separadas | `StartupSecurityValidator`, `AttributeEncryptor`, `TokenHasher` |
| LGPD | Inventário, consentimento, exportação, revogação e exclusão em cascata | `LgpdService`, `LgpdServiceTest`, [`LGPD.md`](LGPD.md) |
| Auditoria | Cadeia HMAC-SHA256 com sequência monotônica, imutabilidade e RBAC | `AuditService`, `AuditIntegrityTest`, [`sql/audit-hardening.sql`](sql/audit-hardening.sql) |
| Documentação/testes | Documentos alinhados ao código e comandos reproduzíveis | [`TESTES.md`](TESTES.md) |
| Correção científica | Argon2id descrito como KDF, não como criptografia; Supabase = PostgreSQL gerenciado | [`RESUMO_CIENTIFICO.md`](RESUMO_CIENTIFICO.md) |

## 2. Autenticação, autorização e 2FA

### Fluxo

```text
[HTTPS] Cliente
   |
   v
POST /perform_login  <-- RateLimitingFilter (10 req/min/IP)
   |
   +-- falha -> LOGIN_FAILED_PASSWORD / ACCOUNT_LOCKED_* (bloqueio de 15 min após 5 falhas)
   |
   +-- sucesso -> LOGIN_PRIMARY_SUCCESS -> /login-2fa
                         |
                         v
                  POST /login-2fa (TOTP RFC 6238)
                         |
                         +-- inválido -> LOGIN_FAILED_2FA
                         +-- válido   -> LOGIN_SUCCESS_2FA, atributo 2FA_VERIFIED na sessão
```

- `TwoFactorEnforcementFilter` é registrado **antes de `AuthorizationFilter`**, portanto uma rota
  administrativa não é acessível apenas com o primeiro fator.
- Rotas sensíveis (dashboard, perfil, privacidade, administração, favoritos, empréstimos e API)
  exigem `2FA_VERIFIED=true`. `/login-2fa` é a única rota autenticada que permite o trânsito sem
  o segundo fator.
- A revogação do consentimento (`consentRevoked=true`) desabilita a conta no `UserDetailsService`
  e o filtro invalida a sessão imediatamente.
- `sessionFixation().migrateSession()` troca o identificador de sessão no login.
- `POST /logout` invalida a sessão e remove `JSESSIONID`.

### Autorização administrativa

- `User.role` é normalizado (`ROLE_ADMIN` → `ADMIN`); e-mails em `SECURITY_ADMIN_EMAILS` também
  recebem `ROLE_ADMIN`.
- O painel `/admin/audit/**` usa `hasRole("ADMIN")`. Usuários comuns recebem `403`, mesmo com 2FA válido.

## 3. Hash de senha e política

`Argon2PasswordEncoder` (OWASP/RFC 9106) com parâmetros configuráveis:

| Parâmetro | Valor |
|---|---|
| saltLength | 16 bytes |
| hashLength | 32 bytes |
| parallelism | 1 |
| memory | 65536 KiB |
| iterations | 3 |

`PasswordHashingSupport` extrai o salt embutido na string PHC e o persiste em `User.passwordSalt`.
Argon2id é uma **função de derivação de chave de senha**, não um algoritmo de criptografia e não
produz a chave AES. A política `PasswordPolicy` exige mínimo de 12 caracteres, maiúscula, minúscula,
dígito, símbolo, rejeita senhas comuns e impede a reutilização da senha atual.

## 4. Recuperação de senha

1. `POST /forgot-password` aceita qualquer e-mail e sempre responde da mesma forma. Para e-mails
   inexistentes, `TokenHasher.dummyHash()` executa o mesmo custo de HMAC, evitando enumeração por timing.
2. O token tem 256 bits, é enviado em claro apenas por e-mail e é gravado como **HMAC-SHA256** em
   `PasswordResetToken.tokenHash` (domínio separado da chave de auditoria).
3. Validade de 15 minutos; um novo pedido revoga os anteriores.
4. `resetPassword()` valida a política, bloqueia a linha com `findByTokenHashForUpdate` e executa
   `consumeIfUnused`; apenas uma requisição concorrente consume o token.
5. Eventos de auditoria são registrados com `userId=null`, de modo que o log não associe o pedido
   ao titular.

## 5. TLS, comunicação e dados em repouso

- `server.port=8443`, `server.ssl.enabled=true`, keystore PKCS12 informado por `SERVER_SSL_KEY_STORE`.
- Nenhum keystore, certificado, senha ou chave é versionado. `StartupSecurityValidator` falha o boot
  se TLS estiver desligado, se o keystore não existir, se a senha for fraca, se a URL de reset não
  usar HTTPS ou se a conexão PostgreSQL não exigir `sslmode=require`.
- Redirecionamento HTTP → HTTPS, HSTS com `max-age=31536000; includeSubDomains`, CSP restritiva,
  `frame-options: deny`, cookies `Secure`, `HttpOnly` e `SameSite=Lax`.
- `AttributeEncryptor`: AES-256-GCM com IV aleatório de 12 bytes para `User.twoFactorSecret`.
- `TokenHasher`: HMAC-SHA256 para tokens de reset. `AuditService`: HMAC-SHA256 para a cadeia de log.
- Chaves AES e HMAC são obrigatoriamente distintas e fornecidas por variáveis de ambiente/cofre.
- A validação do ambiente publicado deve ser executada com `scripts/verify-tls.sh` e registrada em
  [`TESTES.md`](TESTES.md). Certificados expirados ou cadeias incompletas invalidam a evidência.

## 6. Auditoria

- `SecurityAuditLog` possui `sequenceNo` monotônico, `previousHash`, `hmacHash` e `logHash`
  (compatibilidade com painéis antigos).
- O HMAC cobre: sequência, usuário (ou `ANONYMOUS`), tipo de evento, IP, User-Agent, timestamp
  truncado a microssegundos e hash anterior. A comparação é feita em tempo constante.
- A escrita é serializada por um lock justo e pelo `SELECT ... FOR UPDATE` do último evento, evitando
  lacunas e ponteiros duplicados sob concorrência.
- `@PreUpdate`/`@PreRemove` bloqueiam alterações e exclusões via JPA. A migração
  [`docs/sql/audit-hardening.sql`](sql/audit-hardening.sql) aplica restrição equivalente no banco,
  unique index de sequência e trigger de verificação de sequência.
- `GET /admin/audit/analyze` e `.json` exigem `ROLE_ADMIN` e exibem `integrityChainValid`,
  `lastSequence`, contagens e amostra recente.
- Para carga crítica, publique o último `sequenceNo`/`hmacHash` emâncora externa (objeto com
  retenção legal ou registro assinado), conforme procedimento em
  [`ROTACAO_SEGREDOS.md`](ROTACAO_SEGREDOS.md).

## 7. Segredos e histórico

Credenciais antigas de Mailtrap/Supabase/AES aparecem no histórico Git. Elas **não** estão mais nos
arquivos atuais, mas precisam ser rotacionadas no provedor e o histórico precisa ser reescrito.
Veja [`ROTACAO_SEGREDOS.md`](ROTACAO_SEGREDOS.md). O workflow de CI não usa mais `continue-on-error`
para TruffleHog, Trivy ou Semgrep.

## 8. Referências

- RFC 9106 — Argon2
- OWASP Password Storage Cheat Sheet
- NIST SP 800-38D — AES-GCM
- RFC 6238 — TOTP
- RFC 2246/8446 — TLS
- Lei nº 13.709/2018 — LGPD
- Lei nº 12.965/2014 — Marco Civil da Internet
