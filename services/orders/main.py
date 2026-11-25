from fastapi import FastAPI

app = FastAPI(title="Orders Service")

orders = [
    {"id": 1, "user_id": 1, "product_id": 1, "quantity": 2},
    {"id": 2, "user_id": 2, "product_id": 2, "quantity": 1},
]


@app.get("/orders")
def list_orders():
    return orders
