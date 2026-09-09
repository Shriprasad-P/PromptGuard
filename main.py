"""Main entry point for PromptGuard application."""

import uvicorn
from promptguard.config import settings


if __name__ == "__main__":
    uvicorn.run(
        "promptguard.api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False
    )
