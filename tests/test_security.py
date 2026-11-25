from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from gateway.main import app as gateway
from services.products import main as products
from services.users import main as users


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "private.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    (tmp_path / "public.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setattr(users, "KEY_DIR", tmp_path)
    return key


@pytest.fixture
def client(signing_key, monkeypatch):
    monkeypatch.setattr(products, "products", [])
    with TestClient(users.app) as users_client, TestClient(products.app) as products_client:
        with TestClient(gateway) as gateway_client:
            def upstream(request):
                if request.url.port == 8003:
                    target = users_client
                elif request.url.port == 8001:
                    target = products_client
                else:
                    raise AssertionError(f"Unexpected upstream: {request.url}")
                response = target.request(
                    request.method, request.url.path,
                    content=request.content, headers=request.headers,
                )
                return httpx.Response(
                    response.status_code, content=response.content,
                    headers={"content-type": response.headers["content-type"]},
                )

            gateway.state.client._transport = httpx.MockTransport(upstream)
            yield gateway_client


@pytest.fixture
def token_factory(signing_key):
    def create(role):
        return jwt.encode(
            {"sub": "test-user", "role": role, "jti": str(uuid4()),
             "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
            signing_key, algorithm="RS256", headers={"kid": users.public_jwk()["kid"]},
        )
    return create


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_request_without_token_is_rejected(client):
    assert client.get("/products").status_code == 401


@pytest.mark.parametrize("role", ["customer", "user"])
def test_non_admin_cannot_create_products(client, token_factory, role):
    response = client.post(
        "/products", json={"name": "Monitor", "price": 100},
        headers=bearer(token_factory(role)),
    )
    assert response.status_code == 403
    assert products.products == []


def test_spoofed_admin_header_does_not_grant_access(client, token_factory):
    body = {"name": "Monitor", "price": 100}
    assert client.post("/products", json=body, headers={"X-User-Role": "admin"}).status_code == 401

    headers = {**bearer(token_factory("customer")), "X-User-Role": "admin"}
    assert client.post("/products", json=body, headers=headers).status_code == 403
    assert products.products == []

    response = client.post("/products", json=body, headers=bearer(token_factory("admin")))
    assert response.status_code == 201


def test_logged_out_token_is_rejected(client, token_factory):
    headers = bearer(token_factory("customer"))
    assert client.get("/products", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 200
    assert client.get("/products", headers=headers).status_code == 401
