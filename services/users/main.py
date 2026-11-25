import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Users Service")

KEY_DIR = Path(__file__).resolve().parents[2] / "keys"
DEMO_ACCOUNTS = {
    "demo": {
        "id": "1", "role": "user", "salt": b"gateway-demo-salt",
        "password_hash": bytes.fromhex("f34518cea81f3b76f3c0c15eeddaf6c77b5a39b3e05f34c662a1ed0eb6ad6c89"),
    },
    "admin": {
        "id": "2", "role": "admin", "salt": b"gateway-admin-salt",
        "password_hash": bytes.fromhex("aa2270bbd4afab61271ad231dd72151dc454418fc0e9396dd07dd1e20a73905a"),
    },
}


class LoginRequest(BaseModel):
    username: str
    password: str


def public_jwk():
    public_pem = (KEY_DIR / "public.pem").read_bytes()
    public_key = serialization.load_pem_public_key(public_pem)
    kid = hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).hexdigest()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


@app.post("/users/login")
def login(credentials: LoginRequest):
    account = DEMO_ACCOUNTS.get(credentials.username)
    reference = account or DEMO_ACCOUNTS["demo"]
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", credentials.password.encode(), reference["salt"], 600_000
    )
    if not hmac.compare_digest(password_hash, reference["password_hash"]) or account is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    payload = {
        "sub": account["id"],
        "role": account["role"],
        "jti": str(uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    token = jwt.encode(
        payload, (KEY_DIR / "private.pem").read_bytes(), algorithm="RS256",
        headers={"kid": public_jwk()["kid"]},
    )
    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/.well-known/jwks.json")
def jwks():
    return {"keys": [public_jwk()]}

users = [
    {"id": 1, "name": "Alex"},
    {"id": 2, "name": "Sam"},
]


@app.get("/users")
def list_users():
    return users
