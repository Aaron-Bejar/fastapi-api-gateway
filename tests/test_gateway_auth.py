import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from gateway.main import app as gateway
from gateway import main as gateway_module
from services.products import main as products
from services.users import main as users


class GatewayAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.key_dir = Path(cls.directory.name)
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (cls.key_dir / "private.pem").write_bytes(cls.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        (cls.key_dir / "public.pem").write_bytes(cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.key_patch = patch.object(users, "KEY_DIR", self.key_dir)
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)
        self.users_client = TestClient(users.app)
        self.gateway_client = TestClient(gateway)
        self.gateway_client.__enter__()
        self.addCleanup(self.gateway_client.__exit__, None, None, None)
        self.requests = []

        def upstream(request):
            self.requests.append(str(request.url))
            if request.url.port == 8003:
                response = self.users_client.request(
                    request.method, request.url.path, content=request.content,
                    headers={"content-type": request.headers.get("content-type", "")},
                )
                return httpx.Response(response.status_code, content=response.content,
                                      headers={"content-type": response.headers["content-type"]})
            return httpx.Response(200, json=[{"id": 1}])

        gateway.state.client._transport = httpx.MockTransport(upstream)

    def test_login_and_access(self):
        bad = self.gateway_client.post("/users/login", json={"username": "demo", "password": "wrong"})
        self.assertEqual(bad.status_code, 401)
        bad_username = self.gateway_client.post(
            "/users/login", json={"username": "usuário", "password": "learning-gateway"}
        )
        self.assertEqual(bad_username.status_code, 401)
        login = self.gateway_client.post(
            "/users/login", json={"username": "demo", "password": "learning-gateway"}
        )
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]
        response = self.gateway_client.get("/products", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{"id": 1}])
        self.assertIn("http://127.0.0.1:8003/users/.well-known/jwks.json", self.requests)
        self.assertEqual(jwt.get_unverified_header(token)["alg"], "RS256")
        claims = jwt.decode(token, self.private_key.public_key(), algorithms=["RS256"])
        self.assertEqual((claims["sub"], claims["role"]), ("1", "user"))
        self.assertTrue(claims["jti"])

    def test_invalid_tokens_never_reach_products(self):
        kid = users.public_jwk()["kid"]
        payload = {"sub": "1", "role": "user", "jti": "test", "exp": datetime.now(timezone.utc) - timedelta(seconds=1)}
        expired = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": kid})
        payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=1)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(payload, other_key, algorithm="RS256", headers={"kid": kid})
        unknown = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": "unknown"})
        for token in (None, "invalid", expired, forged, unknown):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            self.assertEqual(self.gateway_client.get("/products", headers=headers).status_code, 401)
        self.assertNotIn("http://127.0.0.1:8001/products", self.requests)

    def test_unavailable_jwks_is_not_reported_as_invalid_token(self):
        token = jwt.encode(
            {"sub": "1", "role": "user", "jti": "test", "exp": datetime.now(timezone.utc) + timedelta(minutes=1)},
            self.private_key, algorithm="RS256", headers={"kid": users.public_jwk()["kid"]},
        )
        gateway.state.client._transport = httpx.MockTransport(lambda request: httpx.Response(503))
        response = self.gateway_client.get("/products", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 503)

    def test_identity_spoofing_and_product_rbac(self):
        products_client = TestClient(products.app)
        original_transport = gateway.state.client._transport
        seen = []

        def upstream(request):
            if request.url.port == 8001:
                seen.append(request)
                response = products_client.request(
                    request.method, request.url.path, content=request.content, headers=request.headers
                )
                return httpx.Response(response.status_code, content=response.content,
                                      headers={"content-type": response.headers["content-type"]})
            if request.url.port == 8002:
                seen.append(request)
                return httpx.Response(200, json=[])
            return original_transport.handler(request)

        gateway.state.client._transport = httpx.MockTransport(upstream)
        product = {"name": "Test product", "price": 12.5}
        with patch.object(products, "products", [{"id": 1, "name": "Existing", "price": 1}]):
            user_token = self.gateway_client.post(
                "/users/login", json={"username": "demo", "password": "learning-gateway"}
            ).json()["access_token"]
            spoofed = {"Authorization": f"Bearer {user_token}", "x-user-id": "99", "x-user-role": "admin"}
            response = self.gateway_client.post("/products", json=product, headers=spoofed)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(seen[-1].headers["x-user-id"], "1")
            self.assertEqual(seen[-1].headers["x-user-role"], "user")
            self.assertEqual(len(products.products), 1)

            self.assertEqual(self.gateway_client.get("/orders", headers=spoofed).status_code, 200)
            self.assertEqual(seen[-1].headers["x-user-id"], "1")
            self.assertEqual(seen[-1].headers["x-user-role"], "user")

            admin_token = self.gateway_client.post(
                "/users/login", json={"username": "admin", "password": "admin-gateway"}
            ).json()["access_token"]
            response = self.gateway_client.post(
                "/products", json=product,
                headers={"Authorization": f"Bearer {admin_token}", "X-User-Role": "user"},
            )
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.json(), {"id": 2, **product})
            self.assertEqual(seen[-1].headers["x-user-id"], "2")
            self.assertEqual(seen[-1].headers["x-user-role"], "admin")
            self.assertEqual(len(products.products), 2)

            before = len(seen)
            self.assertEqual(self.gateway_client.post(
                "/products", json=product, headers={"X-User-Role": "admin"}
            ).status_code, 401)
            self.assertEqual(len(seen), before)
            self.assertEqual(products_client.post("/products", json=product).status_code, 403)

    def make_token(self, subject, token_id):
        return jwt.encode(
            {"sub": subject, "role": "user", "jti": token_id,
             "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
            self.private_key, algorithm="RS256", headers={"kid": users.public_jwk()["kid"]},
        )

    def test_logout_revokes_only_current_token_with_expiration(self):
        token = self.make_token("1", "session-a")
        other_token = self.make_token("1", "session-b")
        headers = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.gateway_client.get("/products", headers=headers).status_code, 200)
        self.assertEqual(self.gateway_client.post("/auth/logout", headers=headers).status_code, 200)
        ttl = self.gateway_client.portal.call(gateway.state.redis.ttl, "revoked:session-a")
        self.assertTrue(0 < ttl <= 600)
        self.requests.clear()
        self.assertEqual(self.gateway_client.get("/products", headers=headers).status_code, 401)
        self.assertEqual(self.gateway_client.post("/auth/logout", headers=headers).status_code, 401)
        self.assertNotIn("http://127.0.0.1:8001/products", self.requests)
        self.assertEqual(self.gateway_client.get(
            "/products", headers={"Authorization": f"Bearer {other_token}"}
        ).status_code, 200)

    def test_limit_is_per_user_and_resets_in_next_window(self):
        token = self.make_token("1", "session-a")
        second_token = self.make_token("1", "session-b")
        other_user = self.make_token("2", "session-c")
        start = int(time.time()) // 60 * 60 + 10
        clock = SimpleNamespace(time=lambda: start)
        with patch.object(gateway_module, "time", clock):
            headers = {"Authorization": f"Bearer {token}"}
            for _ in range(30):
                self.assertEqual(self.gateway_client.get("/products", headers=headers).status_code, 200)
            before = self.requests.count("http://127.0.0.1:8001/products")
            response = self.gateway_client.get(
                "/products", headers={"Authorization": f"Bearer {second_token}"}
            )
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers["Retry-After"], "50")
            self.assertEqual(self.requests.count("http://127.0.0.1:8001/products"), before)
            self.assertEqual(self.gateway_client.get(
                "/products", headers={"Authorization": f"Bearer {other_user}"}
            ).status_code, 200)
            clock.time = lambda: start + 60
            self.assertEqual(self.gateway_client.get("/products", headers=headers).status_code, 200)


if __name__ == "__main__":
    unittest.main()
