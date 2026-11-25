from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Products Service")

products = [
    {"id": 1, "name": "Keyboard", "price": 45.0},
    {"id": 2, "name": "Mouse", "price": 25.0},
]


class ProductRequest(BaseModel):
    name: str = Field(min_length=1)
    price: float = Field(ge=0, allow_inf_nan=False)


@app.get("/products")
def list_products():
    return products


@app.post("/products", status_code=201)
def create_product(
    product: ProductRequest,
    user_role: Annotated[str | None, Header(alias="X-User-Role")] = None,
):
    if user_role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    created = {"id": max((item["id"] for item in products), default=0) + 1, **product.model_dump()}
    products.append(created)
    return created
