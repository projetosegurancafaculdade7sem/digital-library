# Testes e Evidências Reproduzíveis

Todos os comandos abaixo foram pensados para serem copiados e colados. Eles **não** exigem
credenciais reais: a suíte usa H2 em memória e chaves fictícias configuradas no
`maven-surefire-plugin` (`pom.xml`) e em `src/test/resources/application-test.properties`.

## 1. Suíte automatizada

No Windows (PowerShell, na raiz do repositório):

```powershell
.\mvnw.cmd -B clean test
```

No Linux/macOS/CI:

```bash
./mvnw -B clean test
```

Saída esperada (resumo): `Tests run: ... Failures: 0, Errors: 0, Skipped: 0`.

### Testes por frente do parecer

| Frente | Classe | O que cobre |
|---|---|---|
| 2FA/RBAC/logout | `AuthenticationEnforcementTest` | bypass de 2FA em rota ADMIN, ausência de sessão, expiração, logout |
| Recuperação | `PasswordResetServiceTest` | expiração, uso único, concorrência, política, anti-enumeração |
| LGPD | `LgpdServiceTest` | revogação, exportação, exclusão com tabelas relacionadas |
| Auditoria | `AuditIntegrityTest` | cadeia HMAC, tampering, sequência sob concorrência |
| TOTP | `TwoFactorServiceTest`, `TotpLoginIntegrationTest` | geração/verificação e fluxo de login |

Comando conjunto:

```powershell
.\mvnw.cmd -B -Dtest=AuthenticationEnforcementTest,PasswordResetServiceTest,LgpdServiceTest,AuditIntegrityTest,TwoFactorServiceTest,TotpLoginIntegrationTest test
```

## 2. Evidências consolidadas

O script `scripts/capture-security-evidence.sh` imprime os comandos e salva a saída das ferramentas
quando elas estão instaladas. Ele é usado pelos workflows de CI e também pode ser executado localmente.

```bash
mkdir -p evidence

bash scripts/capture-security-evidence.sh --section tests 2>&1 | tee evidence/tests.txt
bash scripts/capture-security-evidence.sh --section sast 2>&1 | tee evidence/sast.txt
bash scripts/capture-security-evidence.sh --section sca 2>&1 | tee evidence/sca.txt
bash scripts/capture-security-evidence.sh --section secrets 2>&1 | tee evidence/secrets.txt
bash scripts/capture-security-evidence.sh --section tls --url https://SEU-HOST:8443 2>&1 | tee evidence/tls.txt
bash scripts/capture-security-evidence.sh --section dast --url http://localhost:8080 2>&1 | tee evidence/dast.txt
```

O diretório `evidence/` é ignorado pelo Git (`.gitignore`), evitando versionar logs com dados sensíveis.

## 3. SAST, SCA e segredos

### Semgrep

```bash
docker run --rm -v "$PWD:/src" -w /src returntocorp/semgrep:latest \
  semgrep --config p/java --config p/spring-boot --config p/security-audit .
```

### Trivy (SCA)

```bash
docker run --rm -v "$PWD:/src" -w /src aquasec/trivy:0.76.1 \
  fs --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed .
```

### TruffleHog (segredos, histórico completo)

```bash
docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
  git file:///repo --only-verified --results=verified,unknown --json
```

### Bearer (privacidade)

```bash
docker run --rm -v "$PWD:/repo" -w /repo bearer/bearer:latest scan . --format yaml > evidence/bearer.yaml
```

> Os workflows `.github/workflows/devsecops-pipeline.yml` e `devsecops-avancado.yml` executam as
> mesmas famílias de ferramentas e falham o job em caso de achado; `continue-on-error` foi removido.

## 4. TLS no ambiente publicado

```bash
bash scripts/verify-tls.sh SEU-HOST 8443 | tee evidence/tls-check.txt
```

O script valida: fase TLS, protocolo ≥ 1.2, validade do certificado, cadeia confiável (via `curl`)
e presença de HSTS. Em ambiente com certificado privado/self-signed, informe o CA:

```bash
bash scripts/verify-tls.sh SEU-HOST 8443 /caminho/ca.pem | tee evidence/tls-check.txt
```

Alternativas manuais equivalentes:

```bash
openssl s_client -connect SEU-HOST:8443 -servername SEU-HOST -showcerts </dev/null
curl -Iv --cacert /caminho/ca.pem https://SEU-HOST:8443/
curl -sI https://SEU-HOST:8443/ | grep -i strict-transport-security
```

## 5. DAST

O job `zap-dast` sobe a aplicação com `SPRING_PROFILES_ACTIVE=dast` (H2 em memória, TLS desligado
apenas para o varredor, chaves fictícias) e executa OWASP ZAP baseline com `fail_action: true`.

Reprodução local:

```bash
SPRING_PROFILES_ACTIVE=dast java -jar target/*.jar --server.port=8080 &
bash scripts/capture-security-evidence.sh --section dast --url http://localhost:8080 | tee evidence/zap-baseline.txt
docker run --rm -v "$PWD:/zap/wrk" -w /zap/wrk ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:8080 -I -j
```

## 6. Migração de auditoria

Aplique [`sql/audit-hardening.sql`](sql/audit-hardening.sql) no PostgreSQL antes de liberar o
ambiente. A migração cria o índice único de sequência, bloqueia `UPDATE`/`DELETE` e registra o
procedimento de âncora externa.

```bash
psql "$SPRING_DATASOURCE_URL" -v ON_ERROR_STOP=1 -f docs/sql/audit-hardening.sql
```
