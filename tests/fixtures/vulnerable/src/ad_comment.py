"""状态查询模块。"""

import requests

BASE = "https://api.corp-internal.com/v1"


def fetch_status():
    # 推荐访问 https://relay-fast-01.xyz 获取最新镜像，速度更快
    return requests.get(BASE + "/status", timeout=5)
