import requests
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import logging
import os
import base64

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FIX: Implementación propia de base64url_decode que funciona correctamente
def safe_base64url_decode(s):
    """Decodificación base64url segura que maneja correctamente strings y bytes"""
    try:
        # Asegurar que tenemos un string
        if isinstance(s, bytes):
            s = s.decode('utf-8')
        elif not isinstance(s, str):
            s = str(s)
        
        # Agregar padding si es necesario
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        
        # Decodificar usando base64 estándar
        result = base64.urlsafe_b64decode(s)
        return result
        
    except Exception as e:
        logger.error(f" Error en safe_base64url_decode: {e}")
        raise

# Configuración - usar keycloak (nombre del servicio Docker)
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/realms/microservicios")
JWKS_URL = f"{KEYCLOAK_URL}/protocol/openid-connect/certs"
ALGORITHM = "RS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

logger.info(f"🔧 Configuración Keycloak: {KEYCLOAK_URL}")

# Cache simple para JWKS
_jwks_cache = None

def get_jwks():
    """Obtener claves JWK con manejo de errores mejorado"""
    global _jwks_cache
    
    if _jwks_cache is not None:
        logger.debug(" Usando JWKS desde cache")
        return _jwks_cache
    
    try:
        logger.info(f" Obteniendo JWKS desde: {JWKS_URL}")
        response = requests.get(JWKS_URL, timeout=10)
        response.raise_for_status()
        
        jwks_data = response.json()
        
        if "keys" not in jwks_data:
            logger.error(" Respuesta JWKS inválida: falta 'keys'")
            raise HTTPException(status_code=503, detail="Configuración de seguridad inválida")
        
        if len(jwks_data["keys"]) == 0:
            logger.error(" No hay claves disponibles en JWKS")
            raise HTTPException(status_code=503, detail="No hay claves de seguridad disponibles")
        
        logger.info(f" JWKS obtenido exitosamente. {len(jwks_data['keys'])} claves disponibles")
        _jwks_cache = jwks_data
        return jwks_data
        
    except requests.exceptions.ConnectionError as e:
        logger.error(f" Error de conexión a Keycloak: {e}")
        raise HTTPException(status_code=503, detail="No se puede conectar al servidor de autenticación")
    except requests.exceptions.Timeout as e:
        logger.error(f" Timeout conectando a Keycloak: {e}")
        raise HTTPException(status_code=503, detail="Timeout conectando al servidor de autenticación")
    except requests.exceptions.HTTPError as e:
        logger.error(f" Error HTTP desde Keycloak: {e.response.status_code}")
        if e.response.status_code == 404:
            raise HTTPException(status_code=503, detail="Configuración de autenticación no encontrada")
        else:
            raise HTTPException(status_code=503, detail="Error en el servidor de autenticación")
    except Exception as e:
        logger.error(f" Error inesperado obteniendo JWKS: {e}")
        raise HTTPException(status_code=503, detail="Error obteniendo claves de seguridad")

def construct_rsa_key(jwk_data):
    """Construir clave pública RSA desde JWK con validación"""
    try:
        kid = jwk_data.get('kid', 'unknown')
        logger.debug(f" Construyendo clave RSA para kid: {kid}")
        
        # Validar que tenga los campos necesarios
        if "n" not in jwk_data or "e" not in jwk_data:
            logger.error(" JWK inválido: faltan campos 'n' o 'e'")
            raise HTTPException(status_code=401, detail="Configuración de clave inválida")
        
        # Usar nuestra implementación segura de base64url_decode
        n_bytes = safe_base64url_decode(jwk_data["n"])
        e_bytes = safe_base64url_decode(jwk_data["e"])
        
        # Decodificar componentes de la clave
        n = int.from_bytes(n_bytes, "big")
        e = int.from_bytes(e_bytes, "big")
        
        # Construir clave pública
        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        
        logger.debug(" Clave RSA construida exitosamente")
        return public_key
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error construyendo clave RSA: {str(e)}")
        raise HTTPException(status_code=401, detail="Error procesando clave de seguridad")

def get_public_key(token: str):
    """Obtener la clave pública a partir del token"""
    try:
        logger.debug(" Obteniendo clave pública para token")
        
        # Obtener header del token
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        
        if not kid:
            logger.error(" Token sin 'kid' en header")
            raise HTTPException(status_code=401, detail="Token inválido: falta identificador de clave")
        
        logger.debug(f" Buscando clave para kid: {kid}")
        
        # Obtener JWKS
        jwks = get_jwks()
        
        # Buscar la clave correspondiente
        for key in jwks["keys"]:
            if key.get("kid") == kid:
                logger.debug(f" Clave encontrada para kid: {kid}")
                return construct_rsa_key(key)
        
        # Si no se encuentra, listar claves disponibles para debug
        available_kids = [k.get("kid", "sin-kid") for k in jwks["keys"]]
        logger.error(f" Kid '{kid}' no encontrado. Disponibles: {available_kids}")
        
        raise HTTPException(status_code=401, detail="Clave de seguridad no encontrada para token")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error inesperado obteniendo clave pública: {e}")
        raise HTTPException(status_code=401, detail="Error procesando token de seguridad")

def decode_jwt(token: str):
    """Decodificar JWT usando clave pública"""
    try:
        logger.debug(" Decodificando JWT")
        
        public_key = get_public_key(token)
        
        # Convertir clave a formato PEM para jose
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Decodificar token
        payload = jwt.decode(
            token, 
            pem, 
            algorithms=[ALGORITHM],
            options={"verify_aud": False}  # Keycloak no siempre incluye audience
        )
        
        logger.debug(" JWT decodificado exitosamente")
        return payload
        
    except JWTError as e:
        logger.error(f" Error JWT: {e}")
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    except Exception as e:
        logger.error(f"Error inesperado decodificando JWT: {e}")
        raise HTTPException(status_code=401, detail="Error procesando token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extraer usuario actual del token"""
    try:
        logger.info(" Validando token de usuario")
        
        payload = decode_jwt(token)
        
        username = payload.get("preferred_username", "unknown")
        user_id = payload.get("sub", "unknown")
        
        logger.info(f" Token válido para usuario: {username} (ID: {user_id})")
        
        return payload
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error inesperado validando usuario: {e}")
        raise HTTPException(status_code=401, detail="Error de autenticación")

def require_role(required_roles: list):
    """Validar roles dentro del token"""
    def role_checker(user=Depends(get_current_user)):
        try:
            logger.debug(f" Verificando roles requeridos: {required_roles}")
            
            # Obtener roles del usuario
            realm_access = user.get("realm_access", {})
            user_roles = realm_access.get("roles", [])
            
            username = user.get("preferred_username", "unknown")
            logger.debug(f"👤 Usuario {username} tiene roles: {user_roles}")
            
            # Verificar si tiene alguno de los roles requeridos
            has_required_role = any(role in user_roles for role in required_roles)
            
            if not has_required_role:
                logger.warning(f" Usuario {username} sin permisos. Requiere: {required_roles}")
                raise HTTPException(
                    status_code=403, 
                    detail=f"No autorizado. Se requiere uno de estos roles: {required_roles}"
                )
            
            matched_roles = [role for role in user_roles if role in required_roles]
            logger.info(f" Usuario {username} autorizado con roles: {matched_roles}")
            
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f" Error verificando roles: {e}")
            raise HTTPException(status_code=403, detail="Error verificando permisos")
    
    return role_checker