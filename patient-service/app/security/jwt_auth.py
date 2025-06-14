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
    """
    Decodificación base64url segura que maneja correctamente strings y bytes
    """
    try:
        logger.debug(f" safe_base64url_decode recibió: tipo={type(s)}, valor='{str(s)[:30]}...'")
        
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
        logger.debug(f" Decodificación exitosa: {len(result)} bytes")
        return result
        
    except Exception as e:
        logger.error(f" Error en safe_base64url_decode: {e}")
        raise

# Try importing the original function, but use our safe version
try:
    from jose.utils import base64url_decode as original_base64url_decode
    logger.info(" Importación jose.utils.base64url_decode exitosa")
    logger.info(" Usando implementación propia safe_base64url_decode debido a bug conocido")
    base64url_decode = safe_base64url_decode
except ImportError as e:
    logger.error(f" Error importando base64url_decode: {e}")
    logger.info(" Usando implementación propia como fallback")
    base64url_decode = safe_base64url_decode

# Configuración - CORREGIDO: usar keycloak (nombre del servicio Docker)
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/realms/microservicios")
JWKS_URL = f"{KEYCLOAK_URL}/protocol/openid-connect/certs"
ALGORITHM = "RS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

logger.info(f" Configuración Keycloak: {KEYCLOAK_URL}")
logger.info(f" JWKS URL: {JWKS_URL}")

# Cache simple para JWKS
_jwks_cache = None

def get_jwks():
    """Obtener claves JWK con manejo de errores mejorado"""
    global _jwks_cache
    
    # Usar cache si está disponible (en producción, implementar TTL)
    if _jwks_cache is not None:
        logger.debug(" Usando JWKS desde cache")
        return _jwks_cache
    
    try:
        logger.info(f" Obteniendo JWKS desde: {JWKS_URL}")
        
        response = requests.get(JWKS_URL, timeout=10)
        response.raise_for_status()
        
        jwks_data = response.json()
        
        # Validar respuesta
        if "keys" not in jwks_data:
            logger.error(" Respuesta JWKS inválida: falta 'keys'")
            raise HTTPException(status_code=503, detail="Configuración de seguridad inválida")
        
        if len(jwks_data["keys"]) == 0:
            logger.error(" No hay claves disponibles en JWKS")
            raise HTTPException(status_code=503, detail="No hay claves de seguridad disponibles")
        
        logger.info(f" JWKS obtenido exitosamente. {len(jwks_data['keys'])} claves disponibles")
        
        # Cachear resultado
        _jwks_cache = jwks_data
        return jwks_data
        
    except requests.exceptions.ConnectionError as e:
        logger.error(f" Error de conexión a Keycloak: {e}")
        raise HTTPException(
            status_code=503, 
            detail="No se puede conectar al servidor de autenticación"
        )
    except requests.exceptions.Timeout as e:
        logger.error(f" Timeout conectando a Keycloak: {e}")
        raise HTTPException(
            status_code=503, 
            detail="Timeout conectando al servidor de autenticación"
        )
    except requests.exceptions.HTTPError as e:
        logger.error(f" Error HTTP desde Keycloak: {e.response.status_code}")
        if e.response.status_code == 404:
            raise HTTPException(
                status_code=503,
                detail="Configuración de autenticación no encontrada"
            )
        else:
            raise HTTPException(
                status_code=503,
                detail="Error en el servidor de autenticación"
            )
    except Exception as e:
        logger.error(f" Error inesperado obteniendo JWKS: {e}")
        raise HTTPException(
            status_code=503, 
            detail="Error obteniendo claves de seguridad"
        )

def construct_rsa_key(jwk_data):
    """Construir clave pública RSA desde JWK con validación"""
    try:
        kid = jwk_data.get('kid', 'unknown')
        # FIX: Ensure proper string conversion for logging
        kid_str = str(kid) if kid is not None else 'None'
        logger.info(f" Construyendo clave RSA para kid: {kid_str}")
        
        # Validar que tenga los campos necesarios
        if "n" not in jwk_data or "e" not in jwk_data:
            logger.error(" JWK inválido: faltan campos 'n' o 'e'")
            raise HTTPException(status_code=401, detail="Configuración de clave inválida")
        
        # FIX: Add detailed debugging for JWK components
        n_value = jwk_data['n']
        e_value = jwk_data['e']
        
        logger.info(f" Análisis JWK - Tipo 'n': {type(n_value).__name__}, Tipo 'e': {type(e_value).__name__}")
        logger.info(f" JWK completo disponible: {list(jwk_data.keys())}")
        
        # Print first few chars safely
        try:
            n_preview = str(n_value)[:20] if n_value else "None"
            e_preview = str(e_value)[:20] if e_value else "None" 
            logger.info(f" Valores - n: '{n_preview}...', e: '{e_preview}'")
        except Exception as preview_err:
            logger.error(f" Error en preview: {preview_err}")
        
        # FIX: Ensure n and e are strings before base64 decoding
        if isinstance(n_value, bytes):
            logger.info(" Convirtiendo 'n' de bytes a string")
            n_str = n_value.decode('utf-8')
        elif isinstance(n_value, str):
            logger.info(" 'n' ya es string")
            n_str = n_value
        else:
            logger.error(f" Tipo de 'n' no soportado: {type(n_value)}")
            raise HTTPException(status_code=401, detail="Formato de clave 'n' inválido")
        
        if isinstance(e_value, bytes):
            logger.info(" Convirtiendo 'e' de bytes a string")
            e_str = e_value.decode('utf-8')
        elif isinstance(e_value, str):
            logger.info(" 'e' ya es string")
            e_str = e_value
        else:
            logger.error(f" Tipo de 'e' no soportado: {type(e_value)}")
            raise HTTPException(status_code=401, detail="Formato de clave 'e' inválido")
        
        logger.info(f" Valores finales - n_str tipo: {type(n_str)}, e_str tipo: {type(e_str)}")
        
        # FIX: Usar nuestra implementación segura de base64url_decode
        try:
            logger.info(" Iniciando decodificación base64url con implementación segura...")
            
            n_bytes = base64url_decode(n_str)
            logger.info(f" 'n' decodificado exitosamente - {len(n_bytes)} bytes")
            
            e_bytes = base64url_decode(e_str)
            logger.info(f" 'e' decodificado exitosamente - {len(e_bytes)} bytes")
            
        except Exception as decode_error:
            logger.error(f" Error en decodificación base64url: {str(decode_error)}")
            logger.error(f" Tipo de error: {type(decode_error).__name__}")
            import traceback
            logger.error(f" Stack trace: {traceback.format_exc()}")
            raise HTTPException(status_code=401, detail="Error decodificando clave JWK")
        
        # Decodificar componentes de la clave
        logger.info(" Convirtiendo bytes a enteros...")
        n = int.from_bytes(n_bytes, "big")
        e = int.from_bytes(e_bytes, "big")
        
        logger.info(f" Enteros generados - e: {e}")
        
        # Construir clave pública
        logger.info(" Construyendo clave pública RSA...")
        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        
        logger.info(" Clave RSA construida exitosamente")
        return public_key
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error general construyendo clave RSA: {str(e)}")
        logger.error(f" Tipo de error: {type(e).__name__}")
        import traceback
        logger.error(f" Stack trace: {traceback.format_exc()}")
        raise HTTPException(status_code=401, detail="Error procesando clave de seguridad")

def get_public_key(token: str):
    """Obtener la clave pública a partir del token"""
    try:
        logger.info("🔍 Obteniendo clave pública para token")
        
        # Obtener header del token
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        
        if not kid:
            logger.error(" Token sin 'kid' en header")
            raise HTTPException(status_code=401, detail="Token inválido: falta identificador de clave")
        
        logger.info(f" Buscando clave para kid: {kid}")
        
        # Obtener JWKS
        jwks = get_jwks()
        
        # Log all available keys for debugging
        logger.info(f" Claves disponibles en JWKS: {len(jwks['keys'])}")
        for i, key in enumerate(jwks["keys"]):
            key_kid = key.get("kid", "sin-kid")
            key_type = key.get("kty", "unknown")
            key_alg = key.get("alg", "unknown")
            logger.info(f"   Clave {i}: kid='{key_kid}', kty='{key_type}', alg='{key_alg}'")
        
        # Buscar la clave correspondiente
        for key in jwks["keys"]:
            if key.get("kid") == kid:
                logger.info(f" Clave encontrada para kid: {kid}")
                return construct_rsa_key(key)
        
        # Si no se encuentra, listar claves disponibles para debug
        available_kids = [k.get("kid", "sin-kid") for k in jwks["keys"]]
        logger.error(f" Kid '{kid}' no encontrado. Disponibles: {available_kids}")
        
        raise HTTPException(
            status_code=401, 
            detail=f"Clave de seguridad no encontrada para token"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error inesperado obteniendo clave pública: {e}")
        raise HTTPException(status_code=401, detail="Error procesando token de seguridad")

def decode_jwt(token: str):
    """Decodificar JWT usando clave pública"""
    try:
        logger.info(" INICIANDO decode_jwt")
        
        logger.info(" Llamando get_public_key...")
        public_key = get_public_key(token)
        logger.info(" get_public_key completado exitosamente")
        
        # Convertir clave a formato PEM para jose
        logger.info(" Convirtiendo clave a formato PEM...")
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logger.info(" Conversión PEM exitosa")
        
        # Decodificar token
        logger.info(" Decodificando JWT con clave PEM...")
        payload = jwt.decode(
            token, 
            pem, 
            algorithms=[ALGORITHM],
            options={"verify_aud": False}  # Keycloak no siempre incluye audience
        )
        
        logger.info(" JWT decodificado exitosamente")
        return payload
        
    except JWTError as e:
        logger.error(f" Error JWT específico: {e}")
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    except HTTPException as he:
        logger.error(f" HTTPException en decode_jwt: {he.detail}")
        raise
    except Exception as e:
        logger.error(f" Error inesperado en decode_jwt: {e}")
        logger.error(f" Tipo de error: {type(e).__name__}")
        import traceback
        logger.error(f" Stack trace decode_jwt: {traceback.format_exc()}")
        raise HTTPException(status_code=401, detail="Error procesando token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extraer usuario actual del token"""
    try:
        logger.info(" Validando token de usuario")
        logger.debug(f"Token (primeros 20 chars): {token[:20]}...")
        
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