import redis
import hug
import os
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# with open("resolver-compose.yml", "r") as f:
#     resolver_compose = f.read()

try:
    agent_id = os.environ["AGENT_ID"]
except KeyError:
    agent_id = 101

try:
    address = os.environ["REDIS_ADDRESS"]
except KeyError:
    address = "localhost"

try:
    connection = redis.Redis(host=address)
except Exception as e:
    logger.info(e)

try:
    proxy_address = os.environ["PROXY_ADDRESS"]
except KeyError:
    proxy_address = "localhost"


def save_data(key, message):
    try:
        connection.lpush(key, message)
    except Exception as e:
        logger.info(e)


@hug.post("/{}/sysinfo".format(agent_id))
def sysinfo(body):
    logger.info(body)
    save_data("sysinfo", body)


@hug.post("/{}/create".format(agent_id))
def create(body):
    logger.info(body)
    save_data("create", body)


@hug.post("/{}/upgrade".format(agent_id))
def upgrade(body):
    logger.info(body)
    save_data("upgrade", body)


@hug.post("/{}/request".format(agent_id))
def start(body: dict):
    logger.info(body)
    save_data("upgrade", body)
