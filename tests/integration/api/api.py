import redis
import falcon
import os
import json
import logging


class Sink(object):
    def __init__(self):
        self.agent_id = os.environ.get("AGENT_ID", "101")
        self.address = os.environ.get("REDIS_ADDRESS", "localhost")
        self.proxy_address = os.environ.get("PROXY_ADDRESS", "localhost")
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        try:
            self.connection = redis.Redis(host=self.address)
        except Exception as e:
            self.logger.info(e)

    def save_data(self, key: str, message: str):
        try:
            self.connection.set(key, message)
        except Exception as e:
            self.logger.info(e)

    def save_sysinfo(self, sysinfo: str):
        try:
            self.connection.lpush("sysinfo", sysinfo)
        except Exception as e:
            self.logger.info(e)

    def handle_request(self, req, resp):
        try:
            data = json.loads(req.stream.read().decode("utf-8"))
            if "slack" in req.path.split("/"):
                key = "datacollect"
            elif "uid" in data:
                key = data.get("uid")
            else:
                self.save_sysinfo(json.dumps(data))
                key = None
            if key:
                self.save_data(key, json.dumps(data))
        except Exception as e:
            self.logger.warning("Failed to persist data {}.".format(e))
            resp.status = falcon.HTTP_500
            resp.media = {"status": "failed"}
        else:
            resp.status = falcon.HTTP_200
            resp.media = {"status": "success"}


app = falcon.API()
app.add_sink(Sink().handle_request, prefix="/")
