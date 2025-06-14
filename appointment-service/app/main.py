from fastapi import Request
from fastapi.responses import JSONResponse
import traceback
import logging

logger = logging.getLogger(__name__)

@app.middleware("http")
async def catch_exceptions_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        logger.error("Unhandled exception: %s", traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"}
        )
