from typing import Annotated, List, Union
from fastapi import FastAPI, Path, Body, Cookie, Form, Depends, HTTPException, status
from pydantic import BaseModel, Field

# ===== Google OAuth & JWT utils =====
# main.py
from google_oauth import verify_google_id_token
from auth_utils import create_access_token, get_current_user_email

# ===== FastAPI instance =====
app = FastAPI(title="114-Backend Demo with Google OAuth & JWT")

# ===== Data models =====
class Item(BaseModel):
    name: str
    description: str | None = Field(
        default=None, title="The description of the item", max_length=100
    )
    price: float = Field(gt=0, description="The price must be greater than zero")
    tax: Union[float, None] = None
    tags: list[str] = []

class TokenRequest(BaseModel):
    id_token: str

# ===== Public / test routes =====
@app.get("/")
async def root():
    return {"message": "Hello FastAPI OAuth Demo"}

@app.post("/login")
async def login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    return {"username": username}

# ===== Items CRUD routes =====
@app.get("/items/{item_id}")
async def read_item(item_id):
    return {"item_id": item_id}

'''
@app.get("/items/")
async def read_item(skip: int = 0, limit: int = 10):
    return fake_items_db[skip: skip + limit]

fake_items_db = [
    {"item_name": "Foo"},
    {"item_name": "Bar"},
    {"item_name": "Baz"}
]
'''

@app.get("/items/")
async def read_item(ads_id: Annotated[str | None, Cookie()]) -> list[Item]:
    return {"ads_id": ads_id}

'''
@app.post("/items/")
async def create_item(item: Item):
    item_dict = item.model_dump() #item.dict()
    if item.tax is not None:
        price_with_tax = item.price + item.tax
        item_dict.update({"price_with_tax": price_with_tax})
    return item_dict
'''

@app.post("/items/")
async def create_item(item: Item) -> Item:
    return item

'''
@app.put("/items/{item_id}")
async def update_item(
    item_id: Annotated[int, Path(title="The ID of the item to get", ge=0, le=1000)], 
    q: str | None = None,
    item: Item | None = None,
):
    result = {"item_id": item_id}
    if q:
        result.update({"q":q})
    if item:
        result.update({"item": item})
    return result
'''

@app.put("/items/{item_id}")
async def update_item(item_id: int, item: Annotated[Item, Body(embed=True)]):
    results = {"item_id": item_id, "item": item}
    return results

# ===== Google OAuth / JWT routes =====
@app.post("/auth/google", summary="Google OAuth Login")
async def google_auth(request: TokenRequest):
    """Verify Google ID Token and issue internal JWT"""
    user_info = verify_google_id_token(request.id_token)
    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Google account did not provide email")
    
    access_token = create_access_token(data={"sub": user_email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        }
    }

@app.get("/users/me", summary="Get current user info")
async def read_users_me(current_user: str = Depends(get_current_user_email)):
    """Requires JWT in Authorization header"""
    return {
        "msg": "Successfully authenticated with JWT",
        "user_email": current_user
    }
