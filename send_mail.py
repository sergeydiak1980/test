import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Параметры для отправки письма
sender_email = "your_email@example.com"
receiver_email = "recipient_email@example.com"
subject = "Ошибка привыполнении "

smtp_server = "smtp.example.com"
smtp_port = 587
username = "your_username"
password = "your_password"



def send_email(message):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Письмо успешно отправлено")
    except Exception as e:
        print("Ошибка при отправке письма:", str(e))
    finally:
        server.quit()


