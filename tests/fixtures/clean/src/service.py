"""用户服务：只做业务编排，不直接持有外部实现细节。"""

import os
import subprocess
from typing import List

import requests

API_BASE = os.environ.get("API_BASE", "https://api.internal.corp/v1")


def list_users(limit: int = 10) -> List[dict]:
    response = requests.get(API_BASE + "/users", params={"limit": limit}, timeout=5)
    response.raise_for_status()
    return response.json()


def read_config(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def git_commit(message: str) -> None:
    subprocess.run(["git", "commit", "-m", message], check=True)
