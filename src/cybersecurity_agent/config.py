import os

import dotenv


dotenv.load_dotenv()

def get_nvidia_api_key() -> str:
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise RuntimeError(
            "NVIDIA_API_KEY environment variable is not set. "
            "Export it locally, or pass it at container runtime via "
            "`docker run -e NVIDIA_API_KEY=...` / --env-file (never bake it into the image)."
        )
    return api_key
