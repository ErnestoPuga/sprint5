from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import uvicorn

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# CREAR LA APLICACIÓN FASTAPI PRIMERO
app = FastAPI(
    title="Alerts Service",
    description="Servicio de alertas médicas con notificaciones",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Evento de inicio (AHORA SÍ PUEDE USAR @app porque ya está definido)
@app.on_event("startup")
async def startup_event():
    logger.info(" Iniciando servicio de alertas...")
    logger.info(" Servicio de alertas iniciado correctamente")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info(" Cerrando servicio de alertas...")

# Endpoints básicos
@app.get("/")
async def root():
    return {
        "message": "Alerts Service is running", 
        "version": "1.0.0",
        "service": "alerts"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "alerts",
        "message": "Servicio funcionando correctamente"
    }

# Importar y registrar las rutas DESPUÉS de crear la app
try:
    from app.routes.alerts import router as alerts_router
    app.include_router(alerts_router)
    logger.info(" Rutas de alertas registradas correctamente")
except ImportError as e:
    logger.error(f" Error importando rutas de alertas: {e}")
    logger.info(" El servicio funcionará pero sin las rutas de alertas")

# Punto de entrada para ejecutar directamente
if __name__ == "__main__":
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8002,
        log_level="info"
    )