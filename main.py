from dotenv import load_dotenv
import os

load_dotenv()  

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from google_oauth import verify_google_id_token, exchange_code_for_tokens
from auth_utils import create_access_token, get_current_user_email

app = FastAPI(title="資工 114-Backend 示範專案")

class TokenRequest(BaseModel):
    id_token: str  

class CodeRequest(BaseModel):
    code: str
    redirect_uri: str  

@app.post("/auth/google/code", summary="Exchange code → JWT")
async def google_auth_with_code(request: CodeRequest):

    tokens = exchange_code_for_tokens(request.code, request.redirect_uri)

    google_id_token = tokens.get("id_token")
    if not google_id_token:
        raise HTTPException(status_code=400,detail="Google did not return an id_token")

    user_info = verify_google_id_token(google_id_token)

    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400,detail="Google did not provide the user's email")
    
    access_token = create_access_token(data={"sub": user_email})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        },
        "google_access_token": tokens.get("access_token"),
}

@app.post("/auth/google", summary="Google ID token → Backend JWT")
async def google_auth(request: TokenRequest):

    # Step 1: Verify the Google ID token
    user_info = verify_google_id_token(request.id_token)

    # Step 2: Retrieve the user's email
    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Google did not provide the user's email")
    
    access_token = create_access_token(data={"sub": user_email})

    # Kembalikan response ke frontend
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        }
}

@app.get("/users/me", summary="Dapatkan informasi user saat ini")
async def read_users_me(current_user: str = Depends(get_current_user_email)):
    return {
        "msg":"Successfully passed JWT verification",
        "user_email": current_user
    }

@app.get("/")
def root():
    return {"message": "Hello FastAPI OAuth Demo"}