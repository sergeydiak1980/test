import requests
import json
from datetime import datetime, timedelta
import os
import sqlite3

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
FILE_PATH = f"{datetime.now().strftime('%Y_%m_%d_')}data.json"
DATABASE_PATH = "vulnerabilities.db"

def create_vulnerabilities_table(cursor):
    # Создание таблицы vulnerabilities, если она не существует
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                      (id TEXT PRIMARY KEY, sourceIdentifier TEXT, published TEXT, lastModified TEXT,
                       vulnStatus TEXT, description TEXT, url TEXT)''')

def insert_vulnerability(cursor, vulnerability):
    # Вставка данных в таблицу vulnerabilities
    cursor.execute("INSERT OR IGNORE INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (vulnerability["cve_id"], vulnerability["source_identifier"], vulnerability["published_date"],
                    vulnerability["last_modified_date"], vulnerability["vulnerability_status"],
                    vulnerability["description"], vulnerability["cve_url"]))

def save_vulnerabilities_to_database(vulnerabilities):
    # Подключение к базе данных SQLite
    conn = sqlite3.connect(DATABASE_PATH)
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
    finally:
        conn.close()

def retrieve_data_from_api(start_date, end_date):
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_date_encoded = start_date_str.replace("+", "%2B")
    end_date_encoded = end_date_str.replace("+", "%2B")
    url = f"{BASE_URL}?pubStartDate={start_date_encoded}&pubEndDate={end_date_encoded}"

    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        print("Ошибка при выполнении запроса:", response.status_code)
        return None

def save_data_to_file(data):
    with open(FILE_PATH, "w") as file:
        json.dump(data, file)

def load_data_from_file():
    if os.path.exists(FILE_PATH):
        with open(FILE_PATH, "r") as file:
            return json.load(file)
    return None

def extract_vulnerabilities(data):
    vulnerabilities = []
    for cve_entry in data['vulnerabilities']:
        cve_id = cve_entry['cve']["id"]
        source_identifier = cve_entry['cve']["sourceIdentifier"]
        published_date = cve_entry['cve']["published"]
        last_modified_date = cve_entry['cve']["lastModified"]
        vulnerability_status = cve_entry['cve']["vulnStatus"]
        description = cve_entry['cve']["descriptions"][0]["value"]
        cve_url = cve_entry['cve'].get('references', [{'url': 'NOT URL'}])[0]['url']
        
        vulnerability = {
            "cve_id": cve_id,
            "source_identifier": source_identifier,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "vulnerability_status": vulnerability_status,
            "description": description,
            "cve_url": cve_url
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities

def main():
    # Проверяем наличие сохраненного файла
    data = load_data_from_file()

    if data is None:
        # Если файла нет, выполняем запрос и сохраняем данные в файл
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        data = retrieve_data_from_api(start_date, end_date)

        if data is not None:
            save_data_to_file(data)
    else:
        print("Использую сохраненные данные из файла")

    vulnerabilities = extract_vulnerabilities(data)

    save_vulnerabilities_to_database(vulnerabilities)

if __name__ == "__main__":
    main()
