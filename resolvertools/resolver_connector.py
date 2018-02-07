import requests
import os
import json


class FirewallConnector:
    def __init__(self):
        self.resolver_address = os.environ['LOCAL_RESOLVER_ADDRESS']

    def active_rules(self):
        # returns {} if non are present, if some returns a list of dicts, where dict is a rule
        try:
            req = requests.get("http://{}:8053/daf".format(self.resolver_address))
        except Exception as e:
            raise ConnectionError(e)
        else:
            return req.text

    def create_rule(self, rule: str):
        try:
            req = requests.post("http://{}:8053/daf".format(self.resolver_address), data=rule)
        except Exception as e:
            raise ConnectionError(e)
        else:
            return req.text

    def fetch_rule_information(self, rule_id: str):
        try:
            req = requests.get("http://{}:8053/daf/{}".format(self.resolver_address, rule_id))
        except Exception as e:
            raise ConnectionError(e)
        else:
            return req.text

    def modify_rule(self, rule_id: str, key: str, value: str):
        try:
            req = requests.patch("http://{}:8053/daf/{}/{}/{}".format(self.resolver_address, rule_id, key, value))
        except Exception as e:
            raise ConnectionError(e)
        else:
            return req.text

    def delete_rule(self, rule_id: str):
        try:
            req = requests.delete("http://{}:8053/daf/{}".format(self.resolver_address, rule_id))
        except Exception as e:
            raise ConnectionError(e)
        else:
            return req.text

    def inject_all_rules(self):
        try:
            with open("/etc/whalebone/kresd/rules.txt", "r") as file:
                rules = json.load(file)
            for rule in rules:
                self.create_rule(rule["info"])
        except Exception as e:
            pass
