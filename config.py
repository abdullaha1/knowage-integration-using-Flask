from redis import Redis, RedisError
import os
redis_client = Redis(host="localhost", port=6379, db=0)
scouting_url = os.environ.get('ENGRO_FARMER_SCOUTING', 'http://localhost:8001')
knowage_url = os.environ.get('KNOWAGE_URL', 'http://localhost:8080')
logdir = os.environ.get('LOGS_DIR', '/home/stackweavers/log')
