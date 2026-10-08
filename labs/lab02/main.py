import sys

from labs.lab02.task1 import Admin, User, UserAccount


def run_demo():
    print("=== ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1 ===")

    # 1. Створення користувача та встановлення пароля
    user = User(username="mariya", email="mariya_cyb@domain.com")
    user.set_password("SecretPass123!")
    account = UserAccount(user)
    print(f"Створено користувача: {account['user']}")

    # 2. Невдала спроба входу
    print("\n--- Спроба входу з невірним паролем ---")
    login_fail = account.login("mariya", "WrongPassword", "192.168.1.10")
    print(f"Результат входу: {login_fail} (Очікується: False)")

    # 3. Успішна спроба входу
    print("\n--- Спроба входу з вірним паролем ---")
    login_ok = account.login("mariya", "SecretPass123!", "192.168.1.10")
    print(f"Результат входу: {login_ok} (Очікується: True)")
    print(f"Авторизований: {account.is_authenticated()}")

    # 4. Валідація та зміна email
    print("\n--- Перевірка валідації Email ---")
    try:
        user.email = "bad_email"
    except ValueError as e:
        print(f"Спіймано очікувану помилку: {e}")

    user.email = "new_mariya@domain.org"
    print(f"Оновлено email: {user.email}")

    # 5. Перевірка прав адміністратора (Admin)
    print("\n--- Перевірка класу Admin ---")
    admin = Admin(username="admin_user", email="admin_sec@domain.com")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("DELETE_USER")
    print(f"Інформація про адміна: {admin}")
    print(f"Має право READ_LOGS: {admin.has_permission('READ_LOGS')}")

    # 6. Завершення сеансу (Logout)
    print("\n--- Вихід із системи (Logout) ---")
    account.logout()
    print(f"Авторизований після logout: {account.is_authenticated()}")

    # 7. Виведення логів AuditLog
    print("\n--- Записи журналу аудиту (AuditLog) ---")
    for log in account["audit_log"].show_all():
        print(f"[{log.timestamp}] Користувач: {log.username} | Дія: {log.action}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Для запуску демонстрації використайте команду:")
        print("python -m labs.lab02.main demo")


if __name__ == "__main__":
    main()
