from contextlib import asynccontextmanager
from dataclasses import dataclass
import math
import time
from typing import Annotated

import fakeredis
import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError, PyJWTError
from pydantic import BaseModel


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient(timeout=5.0) as client, fakeredis.FakeAsyncRedis() as redis:
        app.state.client = client
        app.state.redis = redis
        yield


app = FastAPI(title="API Gateway", lifespan=lifespan)

SERVICES = {
    "products": "http://127.0.0.1:8001/products",
    "orders": "http://127.0.0.1:8002/orders",
    "users": "http://127.0.0.1:8003/users",
}

USERS_URL = "http://127.0.0.1:8003"
JWKS_URL = f"{USERS_URL}/users/.well-known/jwks.json"
RATE_LIMIT = 30
WINDOW_SECONDS = 60
bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


class ProductRequest(BaseModel):
    name: str
    price: float


@dataclass(frozen=True)
class Identity:
    user_id: str
    role: str
    token_id: str
    expires_at: int


@app.post("/users/login", tags=["authentication"])
async def login(credentials: LoginRequest, request: Request):
    try:
        upstream = await request.app.state.client.post(
            f"{USERS_URL}/users/login", json=credentials.model_dump()
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Service timed out")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Service unavailable")
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
    )


async def authenticate(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Identity:
    unauthorized = HTTPException(
        status_code=401,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    try:
        header = jwt.get_unverified_header(credentials.credentials)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise unauthorized
    except InvalidTokenError:
        raise unauthorized

    try:
        response = await request.app.state.client.get(JWKS_URL)
        response.raise_for_status()
        keys = response.json()["keys"]
        if not isinstance(keys, list):
            raise ValueError("Invalid JWKS")
    except (httpx.HTTPError, ValueError, KeyError):
        raise HTTPException(status_code=503, detail="Signing keys unavailable")

    matching = [key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]]
    if len(matching) != 1:
        raise unauthorized
    key = matching[0]
    if key.get("kty") != "RSA" or key.get("alg") != "RS256" or key.get("use") != "sig":
        raise HTTPException(status_code=503, detail="Invalid signing key")
    try:
        public_key = jwt.PyJWK.from_dict(key, algorithm="RS256").key
        payload = jwt.decode(
            credentials.credentials,
            public_key,
            algorithms=["RS256"],
            options={"require": ["exp", "sub", "role", "jti"]},
        )
        if not all(isinstance(payload[name], str) and payload[name] for name in ("sub", "role", "jti")):
            raise unauthorized
        identity = Identity(
            user_id=payload["sub"], role=payload["role"],
            token_id=payload["jti"], expires_at=int(payload["exp"]),
        )
    except (PyJWTError, ValueError, TypeError, KeyError):
        raise unauthorized

    if await request.app.state.redis.exists(f"revoked:{identity.token_id}"):
        raise unauthorized
    return identity


@app.post("/auth/logout", tags=["authentication"])
async def logout(request: Request, identity: Annotated[Identity, Depends(authenticate)]):
    remaining = max(1, math.ceil(identity.expires_at - time.time()))
    await request.app.state.redis.set(f"revoked:{identity.token_id}", "1", ex=remaining)
    return {"detail": "Token revoked"}


async def enforce_rate_limit(
    request: Request, identity: Annotated[Identity, Depends(authenticate)]
) -> Identity:
    now = int(time.time())
    window = now // WINDOW_SECONDS
    retry_after = WINDOW_SECONDS - now % WINDOW_SECONDS
    key = f"rate:{identity.user_id}:{window}"
    async with request.app.state.redis.pipeline(transaction=True) as pipeline:
        pipeline.incr(key)
        pipeline.expire(key, retry_after, nx=True)
        count, _ = await pipeline.execute()
    if count > RATE_LIMIT:
        raise HTTPException(
            status_code=429, detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
    return identity


async def forward(service: str, request: Request, identity: Identity, body: dict | None = None):
    url = SERVICES.get(service)
    if url is None:
        raise HTTPException(status_code=404, detail="Service not found")

    try:
        # Construct an allowlist instead of forwarding client-supplied identity headers.
        headers = {}
        if service in ("products", "orders"):
            headers = {"X-User-Id": identity.user_id, "X-User-Role": identity.role}
        if body is None:
            upstream = await request.app.state.client.get(url, headers=headers)
        else:
            upstream = await request.app.state.client.post(url, headers=headers, json=body)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Service timed out")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Service unavailable")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
    )


@app.post("/products")
async def create_product(
    product: ProductRequest, request: Request, identity: Annotated[Identity, Depends(enforce_rate_limit)]
):
    return await forward("products", request, identity, product.model_dump())


@app.get("/{service}")
async def route_request(
    service: str, request: Request, identity: Annotated[Identity, Depends(enforce_rate_limit)]
):
    return await forward(service, request, identity)
