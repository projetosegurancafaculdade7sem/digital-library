# Digital Library

Plataforma acadêmica para busca e organização de livros digitais. A aplicação consulta APIs públicas
(Google Books/Open Library) e redireciona o estudante para a fonte oficial; não hospeda obras com
direitos autorais de terceiros.

## Stack

- **Linguagem:** Java 17+ (compilado para 17; a imagem Docker usa Java 21)
- **Framework:** Spring Boot (MVC + Thymeleaf)
- **Banco de dados:** PostgreSQL gerenciado pelo Supabase (o Supabase é o provedor do serviço, não um motor diferente)
- **Segurança:** Spring Security, Argon2id, TOTP, AES-256-GCM, HMAC-SHA256, TLS
- **Testes:** JUnit 5, Spring Boot Test, H2 em memória
- **DevSecOps:** Trivy, Semgrep, TruffleHog, Bearer, OWASP ZAP

## Arquitetura

```text
Browser (HTTPS)
    ↓
Controllers (Thymeleaf/REST)
    ↓
Services (regras de negócio, LGPD, auditoria, 2FA)
    ↓
Repositories (Spring Data JPA)
    ↓
PostgreSQL no Supabase  ←→  APIs públicas de livros
```

Estrutura real do código:

```text
src/main/java/com/example/demo/
├── config/         # SecurityConfig, StartupSecurityValidator, TLS
├── controller/     # autenticação, perfil, privacidade, administração
├── dto/            # objetos de transporte
├── model/          # entidades JPA
├── repository/     # interfaces Spring Data
├── security/       # filtros, TOTP, política de senha, HMAC
└── service/        # regras de negócio
```

## Segurança

Os controles de autenticação, 2FA, recuperação de senha, criptografia, LGPD e auditoria estão
documentados em:

- [`docs/SEGURANCA.md`](docs/SEGURANCA.md)
- [`docs/LGPD.md`](docs/LGPD.md)
- [`docs/TESTES.md`](docs/TESTES.md)
- [`docs/ROTACAO_SEGREDOS.md`](docs/ROTACAO_SEGREDOS.md)
- [`docs/RESUMO_CIENTIFICO.md`](docs/RESUMO_CIENTIFICO.md)

> **Importante:** nenhuma credencial, keystore ou chave é versionada. Todas vêm de variáveis de
> ambiente/cofre. Credenciais antigas presentes no histórico Git precisam ser rotacionadas no
> provedor e o histórico precisa ser limpo, conforme `docs/ROTACAO_SEGREDOS.md`.

## Configuração local

Variáveis obrigatórias em produção (exemplo sem valores sensíveis):

```text
PORT=8443
SERVER_SSL_ENABLED=true
SERVER_SSL_KEY_STORE=/caminho/fora/do/repo/keystore.p12
SERVER_SSL_KEY_STORE_PASSWORD=<secret>
SPRING_DATASOURCE_URL=jdbc:postgresql://HOST:6543/postgres?sslmode=require
SPRING_DATASOURCE_USERNAME=<user>
SPRING_DATASOURCE_PASSWORD=<secret>
SECURITY_ENCRYPTION_KEY_BASE64=<32 bytes>
SECURITY_AUDIT_HMAC_KEY_BASE64=<32 bytes>
SPRING_MAIL_HOST=<smtp>
SPRING_MAIL_USERNAME=<user>
SPRING_MAIL_PASSWORD=<secret>
MAIL_FROM=<remetente>
MAIL_RESET_BASE_URL=https://SEU-DOMINIO/reset-password
SECURITY_ADMIN_EMAILS=<emails>
```

### Deploy no Render

O Render termina o TLS no proxy da plataforma. Portanto a aplicação deve rodar em HTTP interno
(e confiar em `X-Forwarded-Proto`, já habilitado por `server.forward-headers-strategy=framework`):

```text
SERVER_SSL_ENABLED=false
SECURITY_TLS_REQUIRE=false
SECURITY_DATASOURCE_SSL_REQUIRED=true
```

Todas as demais variáveis da lista acima também são obrigatórias. O arquivo [`render.yaml`](render.yaml)
já traz essa configuração: basta criar o serviço a partir do blueprint e preencher os segredos
(`sync: false`) no painel. Se o deploy falhar, o `StartupSecurityValidator` agora lista **todas**
as variáveis ausentes em uma única mensagem, antes de qualquer bean ser criado.

Para testes, não é necessário configurar nada: o Maven wrapper força o perfil `test` com H2 e
chaves fictícias via `systemPropertyVariables`.

## Comandos

```powershell
# Compilar e testar
.\mvnw.cmd -B clean test

# Empacotar sem testes
.\mvnw.cmd -B package -DskipTests

# Executar com perfil de DAST (H2, sem credenciais reais)
$env:SPRING_PROFILES_ACTIVE = 'dast'
.\mvnw.cmd -B spring-boot:run
```

Consulte [`docs/TESTES.md`](docs/TESTES.md) para os comandos de TruffleHog, Semgrep, Trivy, Bearer,
ZAP e validação TLS.

## Status

**Em desenvolvimento — MVP 1 com endurecimento de segurança aplicado.**

## Autores

Davi Eliote de Carvalho · Luiz Nabarretti · Igor Hajime

Projeto acadêmico — Engenharia de Software.
