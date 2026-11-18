# Rotação de Segredos e Limpeza do Histórico

Credenciais de Mailtrap, Supabase/PostgreSQL e AES/HMAC apareceram no histórico Git deste repositório.
Elas **não** estão mais nos arquivos atuais, mas devem ser tratadas como comprometidas. A rotação é
uma ação externa ao código e é **urgente**.

## 1. Inventário do que rotacionar

| Segredo | Onde era usado | Ação |
|---|---|---|
| Usuário/senha SMTP (Mailtrap) | `SPRING_MAIL_USERNAME` / `SPRING_MAIL_PASSWORD` | Gerar nova credencial no provedor e revogar a antiga |
| Senha do banco Supabase | `SPRING_DATASOURCE_PASSWORD` | Trocar no Supabase; atualizar secrets de CI/CD e produção |
| Chave AES-256 (`SECURITY_ENCRYPTION_KEY_BASE64`) | Cifrar `two_factor_secret` | Gerar nova chave; tokens TOTP antigos precisarão ser reemitidos |
| Chave HMAC de auditoria (`SECURITY_AUDIT_HMAC_KEY_BASE64`) | Cadeia `security_audit_logs` | Gerar nova chave e reiniciar âncora com novo `genesis` documentado |
| Senha/keystore TLS | `SERVER_SSL_KEY_STORE_PASSWORD` | Emitir novo certificado e keystore; não reutilizar o antigo |
| Chaves de API de provedores de livros | Integrações | Rotacionar se aparecerem em logs ou histórico |
| URL base de reset (`MAIL_RESET_BASE_URL`) | E-mails de recuperação | Confirmar domínio HTTPS próprio e sem token de terceiros |

## 2. Gerar novas chaves

```bash
openssl rand -base64 32   # SECURITY_ENCRYPTION_KEY_BASE64
openssl rand -base64 32   # SECURITY_AUDIT_HMAC_KEY_BASE64
```

As chaves AES e HMAC devem ser diferentes. `StartupSecurityValidator` falha o boot se forem iguais,
se não decodificarem 32 bytes ou se usarem valores conhecidos.

## 3. Atualizar ambiente

Nunca escreva segredos em `application.properties`. Use variáveis de ambiente/cofre:

```text
SPRING_DATASOURCE_URL=...
SPRING_DATASOURCE_USERNAME=...
SPRING_DATASOURCE_PASSWORD=...
SPRING_MAIL_HOST=...
SPRING_MAIL_USERNAME=...
SPRING_MAIL_PASSWORD=...
MAIL_FROM=...
MAIL_RESET_BASE_URL=https://...
SECURITY_ENCRYPTION_KEY_BASE64=...
SECURITY_AUDIT_HMAC_KEY_BASE64=...
SERVER_SSL_KEY_STORE=/caminho/fora/do/repo/keystore.p12
SERVER_SSL_KEY_STORE_PASSWORD=...
SECURITY_ADMIN_EMAILS=...
```

Atualize também os `secrets` dos workflows em `.github/workflows/`. O arquivo `.env` e extensões
são ignorados pelo `.gitignore`.

## 4. Invalidar sessões e tokens após a rotação

```sql
UPDATE password_reset_tokens
   SET revoked_at = NOW()
 WHERE used = false AND revoked_at IS NULL;
```

Reinicie todas as instâncias (as sessões HTTP são em memória) e solicite login/2FA novamente.
Usuários com TOTP cifrado pela antiga chave AES precisarão refundar o segredo; comunique isso no
processo de rotação.

## 5. Expurgar o histórico Git

Crie um arquivo temporário **sem** commit com um texto de substituição por linha, por exemplo:

```bash
git filter-repo --replace-text /caminho/fora/do/repo/replace-text.txt
git filter-repo --invert-paths --path src/main/resources/keystore.p12
```

Para repositórios com fork, faça também:

```bash
git push --force --all origin
git push --force --tags origin
```

Avisar colaboradores para reclonar o repositório. Se o GitHub mantiver referências em cache, abra
uma solicitação de remoção de cache de objetos. Mesmo após a limpeza, **a rotação continua obrigatória**:
A limpeza do histórico não substitui a revogação.

## 6. Âncora externa da auditoria

Para cada fechamento de turno (ou no mínimo diariamente), publique o último par
`sequenceNo`/`hmacHash` do painel administrativo em local externo ao banco:

```text
GET /admin/audit/analyze.json   (ROLE_ADMIN)
-> lastSequence, integrityChainValid, recentEventsSample
```

Exemplo de âncora: arquivo assinado com GPG em repositório somente leitura, objeto S3 com
Object Lock/WORM, ou registro em sistema de ticketing com hash imutável. Registre o identificador
externo em `security_audit_anchors.external_ref` (ver `docs/sql/audit-hardening.sql`).

## 7. Verificação final

```bash
docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
  git file:///repo --only-verified --results=verified,unknown --json
git grep -nE '(password|secret|token)[[:space:]]*=[[:space:]]*[^$]' -- '*.properties' '*.yml' '*.java'
```

O comando `git grep` acima é uma triagem: a ausência de saída não substitui o TruffleHog.
