import hashlib  # Імпортуємо бібліотеку для криптографічного хешування (перетворення паролів у нечитабельний рядок)
import hmac  # Імпортуємо бібліотеку для безпечного порівняння хешів (захист від атак за часом)
import os  # Імпортуємо модуль операційної системи для генерації випадкових чисел (для "солі" пароля)
import re  # Імпортуємо модуль регулярних виразів для перевірки правильності формату пошти
from dataclasses import (
    dataclass,  # Імпортуємо інструмент для швидкого створення класів, що зберігають дані
)
from datetime import (  # Імпортуємо класи для роботи з датою, часом та часовими інтервалами
    datetime,
    timedelta,
    timezone,
)

# Константи за вимогами методички
PBKDF2_ITERATIONS = 100_000  # Кількість ітерацій для алгоритму хешування (чим більше, тим складніше зламати)
SESSION_TIMEOUT_SEC = 900  # Максимальний час бездіяльності користувача у секундах (15 хвилин)


# --- ПУНКТ 2: Клас User ---
class User:
    # Регулярний вираз для перевірки email:
    # Локальна частина: починається з латинської літери, 3-64 символи (букви, цифри, _)
    # Домен: принаймні одна крапка
    EMAIL_REGEX = re.compile(
        r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    def __init__(self, username: str, email: str, role: str = "user", active: bool = True):
        self.username = username  # Зберігаємо ім'я користувача
        self.role = role  # Зберігаємо роль (за замовчуванням "user")
        self.active = active  # Статус акаунту (True - активний, False - заблокований)
        self.__password_hash: bytes | None = None  # Приватна змінна для збереження хешу пароля (спочатку порожня)
        self.__password_salt: bytes | None = None  # Приватна змінна для збереження "солі" пароля
        self.email = email  # Встановлюємо email (це автоматично викличе перевірку в @email.setter)

    @property
    def email(self) -> str:
        # Геттер для отримання значення email
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        # Сеттер для перевірки email перед його збереженням
        if not self.EMAIL_REGEX.match(value):  # Якщо email не відповідає регулярному виразу
            raise ValueError(  # Викликаємо помилку з детальним описом
                f"Некоректний формат email: '{value}'. "
                "Локальна частина має починатися з літери і містити від 3 до 64 символів."
            )
        self._email = value  # Якщо все добре, зберігаємо email у захищену змінну

    def set_password(self, password: str) -> None:
        # Метод для встановлення та шифрування нового пароля
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(16)  # Генеруємо 16 випадкових байтів ("сіль" ускладнює злам)
        self.__password_hash = hashlib.pbkdf2_hmac(  # Створюємо надійний хеш пароля
            "sha256",  # Використовуємо алгоритм SHA-256
            password.encode("utf-8"),  # Перетворюємо пароль у байти
            self.__password_salt,  # Додаємо згенеровану "сіль"
            PBKDF2_ITERATIONS,  # Застосовуємо 100 000 ітерацій
        )

    def check_password(self, password: str) -> bool:
        # Метод для перевірки правильності введеного пароля під час входу
        if not self.__password_hash or not self.__password_salt:
            return False  # Якщо пароль ще не встановлено, повертаємо False
        computed_hash = hashlib.pbkdf2_hmac(  # Хешуємо введений пароль з тією ж самою сіллю
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        # Безпечно порівнюємо збережений хеш і щойно згенерований хеш
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        # Метод для деактивації (блокування) користувача
        self.active = False

    def __str__(self) -> str:
        # Метод для красивого виведення інформації про користувача через print()
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Email: {self.email}, Role: {self.role}, Status: {status})"


# --- ПУНКТ 3: Клас Admin (наслідування від User) ---
class Admin(User):  # Успадковуємо всі властивості та методи класу User
    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ):
        # Викликаємо конструктор батьківського класу User і жорстко задаємо роль "admin"
        super().__init__(username=username, email=email, role="admin", active=active)
        if permissions is None:
            self.permissions: set[str] = set()  # Якщо права не передані, створюємо порожню множину (set)
        else:
            self.permissions = set(permissions)  # Перетворюємо передані права у множину для уникнення дублікатів

    def grant_permission(self, permission: str) -> None:
        # Додаємо нове право адміністратору
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        # Забираємо право в адміністратора (discard не видасть помилку, якщо такого права не було)
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        # Перевіряємо, чи має адміністратор конкретне право
        return permission in self.permissions

    def __str__(self) -> str:
        # Додаємо до виводу User інформацію про специфічні права адміністратора
        base_str = super().__str__()  # Отримуємо рядок від батьківського класу User
        perms_str = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_str} [Permissions: {perms_str}]"


# --- ПУНКТ 4: Клас Session ---
class Session:
    def __init__(self, ip: str):
        self.ip = ip  # Зберігаємо IP-адресу, з якої зайшов користувач
        now = datetime.now(timezone.utc)  # Фіксуємо поточний час у стандарті UTC
        self.login_time: datetime = now  # Час початку сеансу
        self.last_activity: datetime = now  # Час останньої активності (на старті співпадає з часом входу)

    def touch(self) -> None:
        # Метод для оновлення часу останньої активності (щоб не викидало з системи)
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        # Перевіряємо, чи не закінчився час сеансу (таймаут)
        if timeout_sec <= 0:
            raise ValueError("Таймаут повинен бути додатним числом секунди.")
        now = datetime.now(timezone.utc)  # Беремо поточний час
        # Якщо з моменту останньої дії пройшло менше часу, ніж дозволено (15 хвилин) - сеанс активний
        return (now - self.last_activity) < timedelta(seconds=timeout_sec)


# --- ПУНКТ 5: Клас AuditLog та AuditRecord ---
@dataclass
class AuditRecord:
    # Проста структура для зберігання одного запису журналу безпеки
    timestamp: datetime  # Точний час події
    username: str  # Логін користувача, що здійснив дію
    action: str  # Назва дії (наприклад: login_success, logout)


class AuditLog:
    def __init__(self):
        self.logs: list[AuditRecord] = []  # Створюємо порожній список для зберігання всіх подій

    def add_log(self, username: str, action: str) -> None:
        # Створюємо новий запис і додаємо його до журналу (паролі сюди передавати категорично заборонено!)
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.logs.append(record)

    def show_all(self) -> list[AuditRecord]:
        # Повертаємо копію всіх записів журналу
        return list(self.logs)


# --- ПУНКТ 6: Клас UserAccount (композиція та магічні методи) ---
class UserAccount:
    # Клас-обгортка, який об'єднує користувача, його поточну сесію та журнал аудиту
    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user  # Прикріплюємо об'єкт користувача
        self.session: Session | None = None  # Сесія спочатку відсутня (користувач не залогінений)
        self.audit_log = audit_log if audit_log is not None else AuditLog()  # Підключаємо журнал аудиту

    def login(self, username: str, password: str, ip: str) -> bool:
        # Процедура авторизації
        if username != self.user.username or not self.user.active:
            # Якщо логін не збігається або акаунт заблоковано - фіксуємо невдалу спробу
            self.audit_log.add_log(self.user.username, "login_failure")
            return False

        if self.user.check_password(password):
            # Якщо пароль правильний, створюємо нову сесію з переданим IP
            self.session = Session(ip)
            self.session.touch()  # Оновлюємо час активності
            self.audit_log.add_log(self.user.username, "login_success")  # Фіксуємо успішний вхід
            return True
        else:
            # Якщо пароль неправильний - фіксуємо невдалу спробу
            self.audit_log.add_log(self.user.username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        # Перевірка, чи авторизований користувач прямо зараз
        if self.session is None:
            return False  # Якщо сесії немає - не авторизований
        # Перевіряємо, чи сесія не "протухла" (через 15 хвилин бездіяльності)
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        # Процедура виходу із системи
        if self.session is not None:
            self.session = None  # Знищуємо сесію
            self.audit_log.add_log(self.user.username, "logout")  # Записуємо подію виходу в журнал

    def __getitem__(self, item: str):
        # Магічний метод, що дозволяє отримувати атрибути як у словника: account["user"]
        allowed = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if item not in allowed:
            raise KeyError(f"Ключ '{item}' заборонений або не існує.")
        return allowed[item]

    def __setitem__(self, item: str, value) -> None:
        # Магічний метод, що дозволяє змінювати атрибути як у словника, але з перевіркою типів даних
        if item == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути об'єктом класу User.")
            self.user = value
        elif item == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути об'єктом класу Session або None.")
            self.session = value
        elif item == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення має бути об'єктом класу AuditLog.")
            self.audit_log = value
        else:
            raise KeyError(f"Зміна атрибута за ключем '{item}' заборонена.")