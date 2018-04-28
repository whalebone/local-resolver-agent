import os
from datetime import datetime

class LogReader:
    def __init__(self):
        self.logging_directory = "/etc/whalebone/logs/"

    def list_files(self):
        try:
            return os.listdir(self.logging_directory)
        except Exception as e:
            raise FileNotFoundError(e)

    def view_log(self, file: str) -> dict:
        logs = {}
        try:
            with open("{}{}".format(self.logging_directory, file), "r") as file:
                for line in file:
                    split_line = line.split("|")
                    logs[split_line[0]] = {"line": split_line[1], "level": split_line[2], "message": split_line[3]}
        except Exception as e:
            raise IOError(e)
        else:
            return logs

    def filter_logs(self, file: str, from_date: str, to_date: str, lvl: str = None):
        logs = self.view_log(file)
        for key, value in dict(logs).items():
            now = datetime.strptime(key, '%Y-%m-%d %H:%M:%S,%f ')
            if lvl is not None:
                if now < datetime.strptime(from_date, '%Y-%m-%dT%H:%M:%S') or now > datetime.strptime(to_date,
                                                                                                  '%Y-%m-%dT%H:%M:%S'):
                    if value["level"] != lvl:
                        del logs[key]
            else:
                if now < datetime.strptime(from_date, '%Y-%m-%dT%H:%M:%S') or now > datetime.strptime(to_date,
                                                                                                      '%Y-%m-%dT%H:%M:%S'):
                    del logs[key]
        return logs

    def delete_log(self, file: str):
        try:
            os.remove("{}{}".format(self.logging_directory, file))
        except Exception as e:
            raise IOError(e)
