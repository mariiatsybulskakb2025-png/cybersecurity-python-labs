"""Головний файл для запуску всіх завдань Лабораторної роботи №1."""

from task1 import run_task1
from task2 import run_task2
from task3 import run_task3


def main():
    print("\n" + "*" * 50)
    print("РОЗПОЧИНАЄМО ВИКОНАННЯ ЛАБОРАТОРНОЇ РОБОТИ №1")
    print("*" * 50 + "\n")

    # Запуск Завдання 1
    run_task1()
    print("\n\n")

    # Запуск Завдання 2
    run_task2()
    print("\n\n")

    # Запуск Завдання 3
    run_task3()

    print("\n" + "*" * 50)
    print("Всі завдання успішно виконані!")
    print("*" * 50 + "\n")


if __name__ == "__main__":
    main()
