import random
import smtplib
from datetime import datetime, timedelta

class OTPManager:
    def __init__(self):
        self.otps = {}
        self.email = ""
        self.app_password = ""  # Contraseña de aplicación
        self.expiration = timedelta(minutes=5)

    def generate_otp(self):
        return str(random.randint(100000, 999999))

    def send_otp_email(self, receiver, otp):
        try:
            message = f"""From: {self.email}
To: {receiver}
Subject: PySafe OTP Verification
Content-Type: text/plain; charset="utf-8"

Tu código de verificación es: {otp}
Válido por {self.expiration.seconds//60} minutos"""

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.email, self.app_password)
                server.sendmail(self.email, receiver, message.encode('utf-8'))
            
            self.otps[receiver] = {
                "otp": otp,
                "expires": datetime.now() + self.expiration
            }
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False

    def verify_otp(self, email, otp):
        record = self.otps.get(email)
        if not record or datetime.now() > record["expires"]:
            return False
        return record["otp"] == otp
