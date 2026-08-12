from fastapi import APIRouter, Header, HTTPException

from app.services.panther_service import PantherService

router = APIRouter()


@router.get("/health")
async def health_check(
    x_panther_host: str | None = Header(None),
    x_panther_token: str | None = Header(None),
) -> dict[str, str]:
    """
    Health check endpoint.

    If credentials are provided, validates the connection to Panther.
    Otherwise, just returns healthy status.
    """
    if x_panther_host and x_panther_token:
        # Test the actual connection
        try:
            service = PantherService(api_host=x_panther_host, api_token=x_panther_token)
            # Try to list alerts with a small page size to test connection
            await service.list_alerts(page_size=1)
            await service.close()
            return {"status": "connected", "host": x_panther_host}
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Failed to connect to Panther: {str(e)}")

    return {"status": "healthy"}


@router.get("/health/ready")
async def readiness_check() -> dict[str, str]:
    """Readiness check endpoint."""
    return {"status": "ready"}
