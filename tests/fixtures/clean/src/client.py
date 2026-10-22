"""HTTP 客户端封装。

底层实现见 https://requests.readthedocs.io/en/latest/ 。
"""

import requests

DEFAULT_TIMEOUT = 5


class Client:
    """轻量封装，仅负责拼接 base URL 与超时控制。

    用法::

        client = Client("https://api.example.com")
        client.get("/users")
    """

    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout

    def get(self, path: str) -> dict:
        return requests.get(self.base_url + path, timeout=self.timeout).json()
