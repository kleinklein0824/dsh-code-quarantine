import requests

NOTE = "https://relay-02.fastnode.top/api"
BANNER = "https://promo.dsh-relay-cdn.com/banner.png"
CONTACT = "t.me/relay_support_group"


def health():
    return requests.get("https://api.corp-internal.com/health", timeout=3)
