from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from urllib.request import urlopen
import json
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

AUTH0_DOMAIN = 'dev-z5zay63vpst0d8cq.eu.auth0.com'
API_AUDIENCE = 'https://symmetrical-rotary-phone-ppxv54pv5xj36pxq.github.dev/'
ALGORITHMS = ['RS256']

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return credentials.credentials

def verify_jwt(token: str):
    jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "Incorrect claims. Please, check the audience and issuer.",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication token.",
                },
                401,
            )
    else:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Unable to find the appropriate key.",
            },
            401,
        )

def requires_auth(token: str = Depends(get_token_auth_header)):
    try:
        payload = verify_jwt(token)
    except AuthError as err:
        raise HTTPException(status_code=err.status_code, detail=err.error)
    return payload

@app.get("/public")
def public():
    return {"message": "Public Endpoint"}

@app.get("/protected")
def protected(payload: dict = Depends(requires_auth)):
    return {
        "message": "Private Endpoint",
        "user": payload,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)