# Local Testing Guide — Reproducing the Traceability Matrix

Step-by-step setup for running ASTF against the four vulnerable targets used in [`docs/TRACEABILITY.md`](TRACEABILITY.md), so anyone on the team can reproduce results (or find new gaps) on their own machine.

**Only test targets you're authorized to test.** These four are intentionally vulnerable practice applications, meant for exactly this. Never point ASTF at anything else without explicit permission — see [Testing Guidelines](TESTING_GUIDELINES.md).

## Prerequisites

- **Docker Desktop**, running
- **Java 21+**
- The ASTF jar — download the [latest release](https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest) or build from source (`mvn clean package -DskipTests`)

---

## 1. VAmPI

```bash
git clone https://github.com/erev0s/VAmPI.git
cd VAmPI
docker-compose up -d
```

Starts two instances: **insecure on port 5002**, secure on 5001 (Mac users: if 5000/5001 conflicts with AirPlay, this compose file already avoids it). First-time setup — hit `GET http://localhost:5002/createdb` once to seed the database.

**To get the two tokens needed for cross-user BOLA testing** (VAmPI's strongest, most valuable finding class):
```bash
# Register two accounts
curl -X POST http://localhost:5002/users/v1/register -H "Content-Type: application/json" \
  -d '{"username":"tester1","password":"Passw0rd!","email":"t1@example.com"}'
curl -X POST http://localhost:5002/users/v1/register -H "Content-Type: application/json" \
  -d '{"username":"tester2","password":"Passw0rd!","email":"t2@example.com"}'

# Log in each to get a token
curl -X POST http://localhost:5002/users/v1/login -H "Content-Type: application/json" \
  -d '{"username":"tester1","password":"Passw0rd!"}'
curl -X POST http://localhost:5002/users/v1/login -H "Content-Type: application/json" \
  -d '{"username":"tester2","password":"Passw0rd!"}'
```

**Run ASTF:**
```bash
java -jar astf.jar -u http://localhost:5002 \
  --token "TESTER1_TOKEN" --secondary-token "TESTER2_TOKEN" \
  -f HTML -o vampi-report.html
```

---

## 2. crAPI

```bash
curl -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip crapi.zip && cd crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

This is a much heavier stack than the others (multiple microservices) — give it a few minutes to fully come up. Main API on **port 8888**.

**Registering two accounts requires email verification** — crAPI ships Mailhog at **http://localhost:8025**. Register each account via the app/API, open Mailhog in a browser, find the verification email, click the link, then log in to get a token. Repeat for a second account.

**Run ASTF:**
```bash
java -jar astf.jar -u http://localhost:8888 \
  --token "TESTER1_TOKEN" --secondary-token "TESTER2_TOKEN" \
  -f HTML -o crapi-report.html
```

---

## 3. DVGA (GraphQL)

```bash
docker pull dolevf/dvga
docker run -d -t -p 5013:5013 -e WEB_HOST=0.0.0.0 --name dvga dolevf/dvga
```

GraphQL endpoint at **http://localhost:5013/graphql**. No authentication needed for most of DVGA's vulnerabilities.

**Run ASTF:**
```bash
java -jar astf.jar -u http://localhost:5013 -f HTML -o dvga-report.html
```

---

## 4. gRPC Goat

```bash
git clone https://github.com/rootxjs/grpc-goat.git
cd grpc-goat
docker compose up --build
```

Nine labs on ports 8001-8009 (lab 006 runs inside the container, no exposed port — filesystem check, explicitly out of scope for ASTF, see `docs/TRACEABILITY.md`). Only labs 001-002 have been tested against so far; 003-009 are open territory if anyone wants to stand them up and try.

**Run ASTF against a specific lab:**
```bash
java -jar astf.jar -u http://localhost:8001 -f HTML -o grpc-lab001-report.html
```

---

## After running: updating the traceability matrix

1. Open the generated HTML report and compare findings against the relevant target's section in [`docs/TRACEABILITY.md`](TRACEABILITY.md).
2. **If a documented vulnerability now fires that's currently marked Miss/N/A** — don't just flip the status. Confirm it's real first: reproduce independently (curl replay, or for state-changing findings like account takeover, actually verify the effect — e.g. log in with a changed password rather than trusting a 2xx response). This project's standing rule: live-verify before considering anything done.
3. **If something that should fire doesn't** — that's a real gap. File a GitHub issue with the specific endpoint/field and what was expected, same format as the existing issues in the tracker.
4. Update the row's Status and Notes in `docs/TRACEABILITY.md` with what you found, and open a PR.

Questions or stuck on setup — ping the `#owasp-community` or open an issue.
