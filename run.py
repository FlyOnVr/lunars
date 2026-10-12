import os
import sys
import traceback

try:
    from app.main import app
except Exception:
    print("=" * 60, flush=True)
    print("Failed to import app.main:", flush=True)
    traceback.print_exc()
    print("=" * 60, flush=True)
    sys.exit(1)

import uvicorn

if __name__ == "__main__":
    host = os.environ.get("LICENSE_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT",
                              os.environ.get("LICENSE_PORT", "8787")))
    uvicorn.run(app, host=host, port=port,
                workers=1, log_level="info")
