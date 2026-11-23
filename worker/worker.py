import os
import time

import redis
from rq import Worker

redis_url = os.environ["REDIS_URL"]
client = redis.Redis.from_url(redis_url)

while True:
    try:
        Worker(["bountydeck"]).work(burst=False)
    except Exception as exc:
        print(f"Worker unavailable: {exc}", flush=True)
        time.sleep(5)
