import datetime

class Post():
    def __init__(self):
        id = 0
        title = ""
        content = ""
        type = 0
        user = ""
        created=datetime.datetime.min

    def link(self):
        if self.type == 0:
            return "/p/{0}".format(str(self.id))
        else: #link
            return self.content
