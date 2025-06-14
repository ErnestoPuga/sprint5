from fastapi import FastAPI 
from app.routes.alerts import router as alert_router

app = FastAPI()
app.include_router(alert_router, prefix="/alerts", tags=["Alertas"])
