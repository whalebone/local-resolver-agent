import requests
import os
import json

class FirewallConnector:
    def __init__(self):
        self.resolver_address = os.environ['LOCAL_RESOLVER_ADDRESS']

    def active_rules(self):
        # returns {} if non are present, if some returns a list of dicts, where dict is a rule
        req = requests.get("http://{}:8053/daf".format(self.resolver_address))
        return req.text

    def create_rule(self, rule: str):
        req = requests.post("http://{}:8053/daf".format(self.resolver_address), data=rule)
        return req.text

    def fetch_rule_information(self, rule_id: str):
        req = requests.get("http://{}:8053/daf/{}".format(self.resolver_address, rule_id))
        return req.text

    def modify_rule(self, rule_id: str, key: str, value: str):
        req = requests.patch("http://{}:8053/daf/{}/{}/{}".format(self.resolver_address, rule_id, key, value))
        return req.text

    def delete_rule(self, rule_id: str):
        req = requests.delete("http://{}:8053/daf/{}".format(self.resolver_address, rule_id))
        return req.text

    def inject_all_rules(self):
        with open("/etc/whalebone/kresd/rules", "r") as file:
            rules = json.load(file)
        for rule in rules:
            self.create_rule(rule["info"])
