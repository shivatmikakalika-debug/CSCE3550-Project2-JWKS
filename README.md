# CSCE 3550 Project 2 — SQLite-backed JWKS Server

A Flask JWKS server that stores RSA private keys in SQLite, signs mock-user JWTs, and publishes unexpired public keys.

## Installation

```cmd
python -m pip install -r requirements.txt
```

## Run

From the project folder:

```cmd
python app.py
```

The database `totally_not_my_privateKeys.db` is created in the current working directory. The server listens on port 8080.

## Endpoints

- `GET /.well-known/jwks.json` returns unexpired RSA public keys.
- `POST /auth` signs a JWT using an unexpired key. HTTP Basic and JSON mock credentials are accepted but not verified.
- `POST /auth?expired=true` signs a JWT using an expired key.

All values passed to SQLite queries use parameter placeholders; the only dynamic SQL operator is chosen from two hard-coded options.

## Tests

```cmd
python -m pytest -v --cov=app --cov-report=term-missing
```

## Screenshots

Include fresh screenshots of the Project 2 Gradebot rubric and the pytest coverage result, with your identifying information visible. Do not reuse Project 1 screenshots.

## Security note

The database contains **unencrypted private keys** for this coursework demonstration. Do not commit it to a public GitHub repository or use these keys in production. The mock authentication is not real user authentication.
