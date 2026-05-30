"""Preset configuration for multi-user ChatGPT Auto Register"""

import os
import secrets

# Admin preset account (created on first run)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "jinzhu2007"

# PostgreSQL connection
DB_URL = os.environ.get("DB_URL", "postgresql://postgres:postgres@localhost:5432/chatgpt_reg")

# JWT
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))

# Scheduler: daily invite key generation
DAILY_INVITE_COUNT = 10
DAILY_INVITE_QUOTA = 20

# Admin default assets
MAILMANAGE_KEY = os.environ.get("MAILMANAGE_KEY", "")
MAILMANAGE_BASE_URL = "https://mailmanage.lizaliza.top"
