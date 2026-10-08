import argparse  # Імпортуємо модуль для створення аргументів командного рядка
import csv  # Імпортуємо модуль для читання CSV-файлів з нашими даними
import json  # Імпортуємо модуль для збереження результатів у форматі JSON
import logging  # Імпортуємо модуль для ведення логів програми[cite: 34]
import re  # Імпортуємо модуль для використання регулярних виразів[cite: 34]
from collections import (
    defaultdict,  # Імпортуємо defaultdict для зручного групування IP за MAC-адресами[cite: 34]
)
from dataclasses import (  # Імпортуємо інструменти для створення класів даних[cite: 34]
    asdict,
    dataclass,
)
from pathlib import (
    Path,  # Імпортуємо Path для безпечної та зручної роботи зі шляхами до файлів
)

# Регулярний вираз для валідації IP-адреси (шукає чотири числа, розділені крапками)[cite: 34]
IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")  # Компілюємо патерн для швидкодії

# Регулярний вираз для валідації MAC-адреси (шукає 6 пар символів 0-9 або A-F)[cite: 34]
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")  # Компілюємо патерн MAC

@dataclass  # Використовуємо декоратор dataclass для створення простого класу зберігання[cite: 34]
class ArpConflict:  # Оголошуємо клас для збереження виявлених конфліктів
    mac_address: str  # Оголошуємо змінну для збереження проблемної MAC-адреси
    associated_ips: list[str]  # Оголошуємо список для збереження всіх IP, які використовують цю MAC

def setup_logger(log_file: str | None) -> logging.Logger:  # Функція для налаштування системи логування
    logger = logging.getLogger("ARPAuditor")  # Створюємо або отримуємо логер з іменем ARPAuditor
    logger.setLevel(logging.INFO)  # Встановлюємо мінімальний рівень повідомлень, які будемо фіксувати
    formatter = logging.Formatter("[%(levelname)s] %(message)s")  # Визначаємо формат тексту логів (наприклад: [INFO] текст)

    console_handler = logging.StreamHandler()  # Створюємо обробник для виведення логів прямо в термінал
    console_handler.setFormatter(formatter)  # Застосовуємо наш формат до термінального обробника
    logger.addHandler(console_handler)  # Прикріплюємо термінальний обробник до логера

    if log_file:  # Якщо користувач передав шлях до файлу логів через CLI
        file_handler = logging.FileHandler(log_file, encoding="utf-8")  # Створюємо обробник для запису у файл
        file_handler.setFormatter(formatter)  # Застосовуємо наш формат до файлового обробника
        logger.addHandler(file_handler)  # Прикріплюємо файловий обробник до логера

    return logger  # Повертаємо повністю налаштований логер

def is_valid_ip(ip: str) -> bool:  # Функція перевірки, чи IP-адреса є правильною[cite: 34]
    if not IP_REGEX.match(ip):  # Якщо рядок не відповідає нашому регулярному виразу IP
        return False  # Одразу повертаємо False (невалідний)
    parts = ip.split(".")  # Розбиваємо IP на 4 окремі числа за крапками
    return all(0 <= int(part) <= 255 for part in parts)  # Перевіряємо, чи кожне число лежить в межах від 0 до 255

def is_valid_mac(mac: str) -> bool:  # Функція перевірки, чи MAC-адреса є правильною[cite: 34]
    return bool(MAC_REGEX.match(mac))  # Повертаємо True, якщо знайдено збіг з регулярним виразом, інакше False

def analyze_arp_table(file_path: Path, logger: logging.Logger) -> tuple[int, int, list[ArpConflict]]:  # Основна функція аналізу
    mac_to_ips: dict[str, set[str]] = defaultdict(set)  # Створюємо словник, де кожній MAC відповідатиме унікальний набір IP[cite: 34]
    valid_count = 0  # Створюємо лічильник для правильних записів у файлі
    invalid_count = 0  # Створюємо лічильник для записів з помилками формату

    try:  # Починаємо безпечний блок коду для роботи з файлом
        with open(file_path, mode="r", encoding="utf-8") as file:  # Відкриваємо CSV-файл у режимі читання
            reader = csv.DictReader(file)  # Створюємо об'єкт для читання CSV, який перетворює рядки у словники[cite: 34]
            for row in reader:  # Перебираємо кожен рядок таблиці
                ip = row.get("IP Address", "").strip()  # Отримуємо значення з колонки 'IP Address' та обрізаємо пробіли[cite: 34]
                mac = row.get("MAC Address", "").strip()  # Отримуємо значення з колонки 'MAC Address' та обрізаємо пробіли[cite: 34]

                if is_valid_ip(ip) and is_valid_mac(mac):  # Якщо і IP, і MAC пройшли перевірку формату[cite: 34]
                    valid_count += 1  # Збільшуємо лічильник валідних записів
                    mac_to_ips[mac].add(ip)  # Додаємо цю IP-адресу у множину адрес для цієї конкретної MAC-адреси[cite: 34]
                else:  # Якщо хоча б одна з адрес має неправильний формат
                    invalid_count += 1  # Збільшуємо лічильник невалідних записів
    except Exception as e:  # Якщо під час відкриття чи читання файлу сталася будь-яка помилка # noqa: BLE001
        logger.error(f"Помилка при читанні файлу: {e}")  # Записуємо текст помилки у логи
        return 0, 0, []  # Повертаємо нульові результати та порожній список конфліктів

    conflicts = []  # Створюємо порожній список для збереження знайдених атак ARP-Spoofing
    for mac, ips in mac_to_ips.items():  # Перебираємо кожну MAC-адресу та її список IP у нашому словнику
        if len(ips) > 1:  # Якщо з цією MAC-адресою пов'язано БІЛЬШЕ ніж 1 IP-адреса (аномалія!)[cite: 34]
            conflicts.append(ArpConflict(mac_address=mac, associated_ips=list(ips)))  # Створюємо об'єкт конфлікту і додаємо в список[cite: 34]

    return valid_count, invalid_count, conflicts  # Повертаємо зібрану статистику та список конфліктів

def main() -> None:  # Точка входу в програму
    parser = argparse.ArgumentParser(description="Аудитор ARP-таблиць та виявлення ARP-Spoofing")  # Створюємо парсер аргументів[cite: 34]
    parser.add_argument("--arp-file", required=True, type=str, help="Шлях до файлу")  # Додаємо аргумент для шляху до вхідного файлу[cite: 34]
    parser.add_argument("--output-json", required=True, type=str, help="Шлях для JSON")  # Додаємо аргумент для шляху збереження JSON[cite: 34]
    parser.add_argument("--detect-spoofing", action="store_true", help="Увімкнути пошук атак")  # Додаємо прапорець для пошуку атак[cite: 34]
    parser.add_argument("--log-file", type=str, help="Шлях до файлу логів")  # Додаємо необов'язковий аргумент для лог-файлу[cite: 34]

    args = parser.parse_args()  # Зчитуємо всі передані команди з термінала
    logger = setup_logger(args.log_file)  # Викликаємо функцію налаштування логера
    arp_path = Path(args.arp_file)  # Перетворюємо переданий шлях до файлу у зручний об'єкт Path

    logger.info(f"Parsing ARP table snapshot from {arp_path}...")  # Виводимо в консоль повідомлення про початок аналізу[cite: 33]

    if not arp_path.exists():  # Якщо файл за вказаним шляхом не існує
        logger.error(f"File not found: {arp_path}")  # Виводимо помилку в лог
        return  # Завершуємо виконання програми

    valid, invalid, conflicts = analyze_arp_table(arp_path, logger)  # Запускаємо головний аналіз таблиці

    logger.info(f"Validated {valid + invalid} IP/MAC entries.")  # Виводимо загальну кількість перевірених рядків[cite: 33]
    print("\n=== Validated Entries Summary ===")  # Друкуємо заголовок статистики у термінал[cite: 33]
    print(f"Valid IP/MAC Pairs : {valid}")  # Друкуємо кількість правильних записів[cite: 33]
    print(f"Invalid Syntax     : {invalid}")  # Друкуємо кількість записів з помилками синтаксису[cite: 33]

    if args.detect_spoofing and conflicts:  # Якщо користувач увімкнув прапорець пошуку атак І конфлікти знайдені
        print("\n=== CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED ===")  # Друкуємо червоний заголовок тривоги[cite: 33]
        for conflict in conflicts:  # Перебираємо кожен знайдений конфлікт
            print("[ALERT] MAC Address Duplicate Conflict!")  # Друкуємо попередження про дублікат[cite: 33]
            print(f"MAC Address: {conflict.mac_address} associated with MULTIPLE IP addresses:")  # Друкуємо проблемну MAC-адресу[cite: 33]
            for ip in conflict.associated_ips:  # Перебираємо всі IP, що прив'язані до цієї MAC
                if ip.endswith(".1"):  # Якщо IP закінчується на .1 (зазвичай це шлюз)
                    print(f"- {ip}  (Default Gateway)")  # Друкуємо IP і позначаємо його як шлюз[cite: 33]
                else:  # Для всіх інших IP-адрес
                    print(f"- {ip}  (Suspicious Host)")  # Друкуємо IP і позначаємо його як підозрілий хост[cite: 33]
            print("-> POSSIBLE MAN-IN-THE-MIDDLE / ARP-SPOOFING ATTACK IN PROGRESS!\n")  # Друкуємо фінальне попередження про атаку[cite: 33]

    output_path = Path(args.output_json)  # Перетворюємо шлях для збереження звіту в об'єкт Path
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Створюємо всі необхідні папки на шляху до файлу, якщо їх немає
    
    with open(output_path, "w", encoding="utf-8") as f:  # Відкриваємо файл для запису звіту
        json.dump([asdict(c) for c in conflicts], f, indent=4)  # Записуємо список конфліктів у формат JSON з відступами для краси[cite: 34]
    
    if args.detect_spoofing and conflicts:  # Якщо ми шукали атаки і знайшли їх
        logger.info(f"Critical conflict logged to {output_path}")  # Записуємо в лог шлях, куди зберегли JSON звіт[cite: 33]

if __name__ == "__main__":  # Перевіряємо, чи скрипт запущено напряму (а не імпортовано в інший файл)
    main()  # Запускаємо точку входу програми