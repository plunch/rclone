import datetime
from flask.ext.login import UserMixin

class User(UserMixin):

    def __init__(self):
        id=0
        name=""
        created=datetime.datetime.min


    def is_authenticated(self):
        return self.id > 0

    def is_active(self):
        return True

    def get_id(self):
        if self.id == 0:
            return None
        return str(self.id);

