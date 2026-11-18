# LGPD — Inventário, Bases Legais e Direitos do Titular

Este documento complementa [`SEGURANCA.md`](SEGURANCA.md) e descreve o tratamento de dados pessoais
implementado em `LgpdService` e no fluxo de cadastro.

## 1. Inventário de dados em repouso

| Dado | Finalidade | Base legal (LGPD) | Retenção | Proteção |
|---|---|---|---|---|
| Nome e e-mail | Autenticação e comunicação acadêmica | Art. 7º, V — execução de contrato | Enquanto a conta estiver ativa | TLS em trânsito; controle de acesso no banco |
| Telefone | Contato e recuperação de acesso/2FA | Art. 7º, V | Até revogação ou exclusão | TLS; AES-256-GCM quando aplicável a segredo |
| Hash Argon2id e salt | Verificação de credencial | Art. 7º, V c/c Art. 5º, II | Durante a conta | KDF com 64 MiB/3 iterações; salt por senha |
| Segredo TOTP | Segundo fator | Art. 7º, V | Até desativação do 2FA | AES-256-GCM com IV aleatório e chave fora do banco |
| IP e User-Agent | Auditoria de segurança e registros de conexão | Art. 7º, V e IX; Art. 15 do Marco Civil | 180 dias | Cadeia HMAC-SHA256; log imutável |
| Favoritos | Organização acadêmica do estudante | Art. 7º, V | Até exclusão do titular | Removidos na exclusão |
| Tokens de recuperação | Redefinição de senha | Art. 7º, V | 15 minutos; revogados após uso | HMAC-SHA256, nunca armazenados em claro |
| Cópias de backup | Recuperação de desastre | Art. 7º, V e IX | 30 dias | Criptografadas; restauração reaplica exclusões |
| Registros de auditoria | Prestação de contas e investigação de incidentes | Art. 7º, V e IX | 180 dias | HMAC, sequência monotônica, âncora externa |

> **Observação operacional:** a retenção de backups é uma política de infraestrutura. Em cada
> restauração, o processo deve reaplicar `LgpdService.deletePersonalData` para titulares excluídos
> e expurgar o backup após o prazo de 30 dias. Essa etapa depende do procedimento do provedor/DBA.

## 2. Consentimento

- `POST /register` exige `termsAccepted` e grava `UserConsent` com versão do termo, finalidade, IP e
  User-Agent.
- `UserService.PURPOSE_ACCOUNT` é a finalidade de conta. O aceite é registrado via
  `LgpdService.registerConsent`.
- Eventos: `LGPD_CONSENT_GRANTED_<purpose>` e `LGPD_CONSENT_REVOKED_<purpose>`.

## 3. Direitos do titular

| Direito | Endpoint / serviço | Comportamento |
|---|---|---|
| Confirmação e consulta | `GET /privacy/my-data` | Retorna dados cadastrais, consentimentos e favoritos |
| Portabilidade | `GET /privacy/export` | JSON com dados pessoais, favoritos e inventário |
| Histórico de consentimentos | `GET /privacy/consents` | Lista ordenada pela data de concessão |
| Revogação | `POST /privacy/consent/revoke` | Marca `consentRevoked=true`, desabilita login, revoga tokens ativos e invalida a sessão |
| Exclusão | `POST /privacy/delete` | Anonimiza o usuário e apaga favoritos, tokens e consentimentos |

Na exclusão, `User.name` passa a `Titular Removido`, o e-mail é substituído por endereço opaco
`deleted-<uuid>@anon.local`, telefone, hash/salt, segredo TOTP e 2FA são removidos. Os eventos
`LGPD_CONSENT_REVOKED_ACCOUNT` e `LGPD_DATA_DELETED` permanecem na auditoria com o identificador
opaco, preservando a cadeia de integridade sem manter dados de identificação.

## 4. Testes

`LgpdServiceTest` cobre:

- revogação desabilita o usuário e revoga tokens;
- exportação inclui dados, favoritos e inventário;
- exclusão remove registros relacionados e anonimiza o titular.

Execute com:

```powershell
.\mvnw.cmd -B -Dtest=LgpdServiceTest test
```
