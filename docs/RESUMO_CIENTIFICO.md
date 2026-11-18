# Resumo científico

Este trabalho apresenta o endurecimento de segurança de uma biblioteca digital acadêmica
implementada em Spring Boot, com persistência em PostgreSQL gerenciado pelo Supabase. Importa
esclarecer que Supabase não é um motor de banco distinto: é uma plataforma que expõe PostgreSQL,
com autenticação, API e hospedagem. Assim, a validação de `sslmode=require` e a migração
`ddl-auto=validate` aplicam-se ao mesmo SGBD relacionado.

A autenticação usa Argon2id como função de derivação de senha, com salt de 16 bytes, 64 MiB de
memória e três iterações. Argon2id não é algoritmo de criptografia e seu digest não é uma chave
criptográfica; a cifragem do segredo TOTP em repouso emprega AES-256-GCM com IV aleatório e chave
independente. Essa distinção corrige a afirmação anterior de que “bcrypt seria usado como chave”:
bcrypt e Argon2id derivam verificadores de senha, enquanto AES exige chave simétrica própria. O
código adota Argon2id, não bcrypt.

O segundo fator TOTP é exigido por um filtro executado antes da autorização, impedindo bypass em
rotas administrativas. A sessão é migrada no login, o painel de auditoria exige `ROLE_ADMIN` e a
revogação de consentimento desativa o usuário. A recuperação de senha utiliza token aleatório de
256 bits armazenado como HMAC-SHA256, validade de 15 minutos, consumo atômico e resposta neutra
para e-mails inexistentes.

A conformidade com a LGPD é tratada por inventário de dados, bases legais, retenção, exportação,
revogação e exclusão de registros relacionados. A auditoria passou de uma cadeia SHA-256 simples
para HMAC-SHA256 com chave externa, sequência monotônica, imutabilidade por JPA e restrições SQL.
A evidência é reproduzível por testes com H2, scripts de TLS e workflows que executam TruffleHog,
Semgrep, Trivy, Bearer e OWASP ZAP sem `continue-on-error`.

**Palavras-chave:** segurança de aplicações; Argon2id; TLS; LGPD; auditoria imutável.
