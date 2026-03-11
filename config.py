import os
from dotenv import load_dotenv

# Выгрузка переменных из файла .env
load_dotenv()

# Настройка API
VT_API_KEY = os.getenv("VT_API_KEY")
VT_API_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Пути к каталогам / файлам
LOGS_FILE = os.getenv("LOGS_FILE", "data/suricata_logs.json")
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")
DATA_DIR = os.getenv("DATA_DIR", "data")

# Настройки запросов
API_TIMEOUT = 10
API_RATE_LIMIT_DELAY = 16  # Лимит бесплатного API - 4 в минуту