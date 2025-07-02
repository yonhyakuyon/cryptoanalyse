import random
import math
import sys
from pathlib import Path

# Русский алфавит (33 буквы)
alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
n_letters = len(alphabet)

# Проверка наличия NumPy для биномиального и пуассоновского распределений
try:
    import numpy as np

    has_numpy = True
except ImportError:
    has_numpy = False


def generate_uniform(key_length: int) -> str:
    """Генерация ключа с равномерным распределением"""
    return "".join(random.choices(alphabet, k=key_length))


def generate_normal(key_length: int, mu: float = 16.0, sigma: float = 5.0) -> str:
    """Генерация ключа с нормальным распределением"""
    key = []
    for _ in range(key_length):
        x = random.gauss(mu, sigma)
        idx = int(round(x)) % n_letters
        key.append(alphabet[idx])
    return "".join(key)


def generate_binomial(key_length: int, n: int = 32, p: float = 0.5) -> str:
    """Генерация ключа с биномиальным распределением"""
    if has_numpy:
        samples = np.random.binomial(n, p, key_length)
    else:
        samples = [
            sum(1 for _ in range(n) if random.random() < p) for _ in range(key_length)
        ]

    key = []
    for s in samples:
        idx = s % n_letters
        key.append(alphabet[idx])
    return "".join(key)


def generate_poisson(key_length: int, lam: float = 16.0) -> str:
    """Генерация ключа с пуассоновским распределением"""
    if has_numpy:
        samples = np.random.poisson(lam, key_length)
    else:
        samples = []
        for _ in range(key_length):
            L = math.exp(-lam)
            k = 0
            p = 1.0
            while p > L:
                k += 1
                p *= random.random()
            samples.append(k - 1)

    key = []
    for s in samples:
        idx = s % n_letters
        key.append(alphabet[idx])
    return "".join(key)


def generate_gamma(key_length: int, alpha: float = 9.0, beta: float = 2.0) -> str:
    """Генерация ключа с гамма-распределением (сигма)"""
    key = []
    for _ in range(key_length):
        x = random.gammavariate(alpha, beta)
        idx = int(round(x)) % n_letters
        key.append(alphabet[idx])
    return "".join(key)


def save_key_to_file(key: str, filename: str):
    """Сохраняет ключ в файл, добавляя в конец файла"""
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(key + "\n")
        print(f"Ключ успешно сохранён в файл: {filename}")
    except Exception as e:
        print(f"Ошибка при сохранении ключа: {e}")


def main():
    """Основная функция программы"""
    print("Генератор ключей для шифра Виженера")
    print("Доступные распределения:")
    print("1 - Нормальное")
    print("2 - Биномиальное")
    print("3 - Пуассоновское")
    print("4 - Гамма (сигма)")
    print("5 - Равномерное")

    try:
        dist_type = int(input("Выберите тип распределения (1-5): "))
        key_length = int(input("Введите длину ключа: "))
    except ValueError:
        print("Ошибка: введите целое число")
        sys.exit(1)

    generators = {
        1: generate_normal,
        2: generate_binomial,
        3: generate_poisson,
        4: generate_gamma,
        5: generate_uniform,
    }

    if dist_type not in generators:
        print("Ошибка: неверный тип распределения")
        sys.exit(1)

    generator = generators[dist_type]
    key = generator(key_length)

    print("\nСгенерированный ключ:")
    print(key)

    # Запрос на сохранение
    save_option = input("\nСохранить ключ в файл? (y/n): ").strip().lower()
    if save_option == "y":
        filename = "keys.txt"
        save_key_to_file(key, filename)


if __name__ == "__main__":
    main()
