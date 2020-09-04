from datetime import datetime, timedelta
import sys


def healthcheck():
    with open("/etc/whalebone/logs/agent-status.log", "r") as log:
        for line in log:
            pass
        splitted_line = line.split(" | ")
        if (datetime.now() - datetime.strptime(splitted_line[0], "%Y-%m-%d %H:%M:%S,%f")) < timedelta(minutes=2):
            if all(error_word not in splitted_line[-1] for error_word in ("error", "Failed")):
                if all(word in splitted_line[-1] for word in
                       ("local_resolver_agent_app", "listen", "ping sent pong received")):
                    return "OK"
        sys.exit(1)


if __name__ == '__main__':
    healthcheck()