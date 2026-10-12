import os
import uvicorn

if __name__ == "__main__":
    host = os.environ.get("LICENSE_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT",
                              os.environ.get("LICENSE_PORT", "8787")))
    uvicorn.run("app.main:app", host=host, port=port,
                workers=1, log_level="info")
