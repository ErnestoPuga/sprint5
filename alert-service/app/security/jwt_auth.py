import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from jose.utils import base64url_decode

# Configuración Keycloak
KEYCLOAK_URL = "http://keycloak:8080/realms/microservicios"
JWKS_URL = f"{KEYCLOAK_URL}/protocol/openid-connect/certs"
ALGORITHM = "RS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Obtener y cachear la clave pública de Keycloak
_jwks = None
def get_jwks():
    global _jwks
    if _jwks is None:
        resp = requests.get(JWKS_URL)
        resp.raise_for_status()
        _jwks = resp.json()
    return _jwks

def get_public_key(token):
    jwks = get_jwks()
    headers = jwt.get_unverified_header(token)
    for key in jwks["keys"]:
        if key["kid"] == headers["kid"]:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key)
    raise HTTPException(status_code=401, detail="No se encontró la clave pública adecuada.")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        public_key = get_public_key(token)
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM], audience=None)
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def require_role(required_roles: list):
    def role_checker(user: dict = Depends(get_current_user)):
        # Keycloak pone los roles en realm_access/roles
        roles = user.get("realm_access", {}).get("roles", [])
        if not any(role in roles for role in required_roles):
            raise HTTPException(status_code=403, detail="No autorizado")
        return user
    return role_checker
