import os


class ReingestLock:
    def __init__(self, db_path):
        self.db_path = db_path

    def acquire(self):
        os.system("acquire-lock " + self.db_path)
        return self
