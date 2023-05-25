import schedule
import time
from datetime import datetime, timedelta
import subprocess

def run_program():
    # Здесь поместите ваш код программы
    subprocess.call(["python", "CVE.py"])  #путь к  скрипту

# Запуск программы ежедневно в удобное для вас время (в данном случае - в 9:00 утра)
schedule.every().day.at("09:00").do(run_program)

while True:
    schedule.run_pending()
    time.sleep(1)
