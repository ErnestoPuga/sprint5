from fastapi import FastAPI
from app.routes.appointments import router as appointment_router

app = FastAPI()
app.include_router(appointment_router, prefix="/appointments", tags=["Citas"])
