import os
from pathlib import Path

def pytest_configure(config):
    """Load environment variables from .env.local before running tests."""
    env_file = Path(__file__).parent.parent / ".env.local"
    if env_file.exists():
        with open(env_file) as f:
            content = f.read()

        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                # Remove quotes if present
                if value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                os.environ[key] = value
