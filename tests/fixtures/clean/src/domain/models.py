"""领域模型：纯数据结构，不依赖任何框架或驱动。"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    id: int
    name: str
    email: str
    created_at: Optional[datetime] = None

    def display_name(self) -> str:
        return self.name.strip() or "anonymous"
