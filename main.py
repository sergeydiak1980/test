import requests
import json
from datetime import datetime, timedelta
import os
import sqlite3
from send_mail import send_email

base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
file_path = f"{datetime.now().strftime('%Y_%m_%d_')}data.json"
database_path = "vulnerabilities.db"

def create_vulnerabilities_table(cursor):
    # Создание таблицы vulnerabilities, если она не существует
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                      (id TEXT PRIMARY KEY, sourceIdentifier TEXT, published TEXT, lastModified TEXT,
                       vulnStatus TEXT, description TEXT, cvssScore TEXT, url TEXT)''')

def insert_vulnerability(cursor, vulnerability):
    # Вставка данных в таблицу vulnerabilities
    cursor.execute("INSERT OR IGNORE INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (vulnerability["cve_id"], vulnerability["source_identifier"], vulnerability["published_date"],
                    vulnerability["last_modified_date"], vulnerability["vulnerability_status"],
                    vulnerability["description"], vulnerability["cvss_score"], vulnerability["cve_url"]))

def save_vulnerabilities_to_database(vulnerabilities):
    # Подключение к базе данных SQLite
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    try:
        create_vulnerabilities_table(cursor)  # Создание таблицы, если она не существует

        # Вставка каждой уязвимости в базу данных
        for vulnerability in vulnerabilities:
            insert_vulnerability(cursor, vulnerability)

        # Сохранение изменений и закрытие соединения с базой данных
        conn.commit()
    except sqlite3.Error as e:
        print("Ошибка при работе с базой данных:", e)
        send_mail("Ошибка при работе с базой данных:    \n"+  e)
    finally:
        conn.close()

def load_data_from_file(file_path):
    # Проверка наличия сохраненного файла и загрузка данных из него
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            data = json.load(file)
            return data
    else:
        return None

def download_data_and_save_to_file(url, file_path):
    # Загрузка данных по указанному URL и сохранение в файл
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        with open(file_path, "w") as file:
            json.dump(data, file)
        return data
    else:
        print("Ошибка при выполнении запроса:", response.status_code)
        send_mail("Ошибка при выполнении запроса:  \n" + response.status_code)
        return None

def retrieve_vulnerabilities(data):
    # Извлечение данных об уязвимостях из загруженных данных
    vulnerabilities = []
    for cve_entry in data['vulnerabilities']:
        cve_id = cve_entry['cve']["id"]
        source_identifier = cve_entry['cve']["sourceIdentifier"]
        published_date = cve_entry['cve']["published"]
        last_modified_date = cve_entry['cve']["lastModified"]
        vulnerability_status = cve_entry['cve']["vulnStatus"]
        description = cve_entry['cve']["descriptions"][0]["value"]
        try:
            cvss_score = cve_entry['cve']['metrics']['cvssMetricV31'][1]['cvssData']['baseScore']
        except Exception as error:
            print ('Error retrieving    cvss    score')
            cvss_score = 'NOT AVAILABLE' 
        try:
            cve_url = cve_entry['cve']['references'][0]['url']
        except Exception as error:
            print ('URL:  not available    ')
            cve_url = 'not available'
            
            
        
        vulnerability = {
            "cve_id": cve_id,
            "source_identifier": source_identifier,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "vulnerability_status": vulnerability_status,
            "description": description,
            "cvss_score": cvss_score,
            "cve_url": cve_url
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities

def main():
    # Проверка наличия сохраненного файла
    data = load_data_from_file(file_path)

    if not data:
        # Если файл не существует, выполняем запрос и сохраняем данные в файл
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_date_encoded = start_date_str.replace("+", "%2B")
        end_date_encoded = end_date_str.replace("+", "%2B")
        url = f"{base_url}?pubStartDate={start_date_encoded}&pubEndDate={end_date_encoded}"

        data = download_data_and_save_to_file(url, file_path)

    if data:
        vulnerabilities = retrieve_vulnerabilities(data)
        save_vulnerabilities_to_database(vulnerabilities)

# Запуск основной логики программы
if __name__ == "__main__":
    main()
