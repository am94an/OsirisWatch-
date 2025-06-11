import ssl
from django.core.mail.backends.smtp import EmailBackend

class NonSSLVerifiedEmailBackend(EmailBackend):
    def open(self):
        if self.connection:
            return False
        self.connection = self.connection_class(
            self.host,
            self.port,
            timeout=self.timeout
        )
        self.connection.starttls(context=ssl._create_unverified_context())
        self.connection.login(self.username, self.password)
        return True
