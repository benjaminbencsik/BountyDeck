from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import datetime, timezone

import redis
from rq import Worker

REDIS_URL = os.environ["REDIS_URL"]
DB_PATH = os.environ.get("BOUNTYDECK_DB", "/data/bountydeck.sqlite3")


def execute_job(job_id: int) -> dict:
    """Reserved for future approved execution. This function performs no network activity."""
    raise RuntimeError("Scanner execution is disabled until scope and authorization records are approved")


if __name__ == "__main__":
    client = redis.Redis.from_url(REDIS_URL)
    Worker(["bountydeck"], connection=client).work(burst=False)
