# Test for access token expiry timer, refresh token, permissions, roles


from fastapi import FastAPI, Depends, HTTPException, status
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
from functools import lru_cache

app = FastAPI()

# Auth0 configuration
AUTH0_DOMAIN = "dev-dunuavrz3gvrmql7.eu.auth0.com"
API_IDENTIFIER = "https://refactored-guide-rpj95qp99wgc5q7p-8000.app.github.dev/"
ALGORITHMS = ["RS256"]

@lru_cache(maxsize=1)
def get_jwks():
    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.json()

def get_rsa_key(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    jwks = get_jwks()
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unable to find appropriate key",
        headers={"WWW-Authenticate": "Bearer"},
    )

def verify_token(token: str):
    try:
        rsa_key = get_rsa_key(token)
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_IDENTIFIER,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    return verify_token(token.credentials)

@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": "You have accessed a protected route!", "user": current_user}


# async def get_current_user(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
#     return get_user_info(token.credentials)

# @app.get("/protected")
# async def protected_route(current_user: dict = Depends(get_current_user)):
#     return {"message": "You have accessed a protected route!", "user": current_user}

@app.get("/")
async def root():
    return {"message": "Hello, World!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)