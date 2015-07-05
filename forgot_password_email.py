 #!/usr/bin/env python

import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class Mailer():
    def __init__(self, smtp, email_from):
        self.s = smtp #smtplib.SMTP('localhost')
        self.me = email_from
        pass

    def close(self):
        self.s.quit()

    def send_forgot_password(self, password, email, user):
        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Reset password for " + user.name
        msg['From'] = self.me
        msg['To'] = email

        # Create the body of the message (a plain-text and an HTML version).
        text = "Hello {0}!\nYour new passrod is {1}".format(user.name, password)
        html = """\
        <html>
        <head></head>
        <body>
            <p>Hello {0}!<br>
            Your new password is {1}
            </p>
        </body>
        </html>
        """.format(user.name, password)

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
    
        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        msg.attach(part1)
        msg.attach(part2)

        # Send the message via local SMTP server.
        # sendmail function takes 3 arguments: sender's address, recipient's address
        # and message to send - here it is sent as one string.
        self.s.sendmail(self.me, email, msg.as_string())
