import vigenere
import cryptoanalysis
import os
import time
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import math


# Функция для вычисления энтропии ключа
def calculate_entropy(key):
    if len(key) == 0:
        return 0.0

    counter = Counter(key)
    total = len(key)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# Функция для определения типа распределения ключа
def detect_key_distribution(key):
    if len(key) == 0:
        return "unknown"

    # Проверка на равномерное распределение
    counter = Counter(key)
    max_count = max(counter.values())
    if max_count / len(key) < 0.15:  # Пороговое значение
        return "uniform"

    # Проверка на повторяющиеся паттерны
    if len(set(key)) < 5:  # Очень мало уникальных символов
        return "repeating"

    # Другие проверки можно добавить здесь
    return "other"


# Функция для сравнения ключей
def compare_keys(original, found):
    if len(original) == 0 or len(found) == 0:
        return 0.0

    min_len = min(len(original), len(found))
    matches = sum(1 for i in range(min_len) if original[i] == found[i])
    return matches / min_len * 100


def main():
    INPUT_FILE = "input.txt"
    OUTPUT_FILE = "results.txt"
    KEYS_FILE = "keys.txt"  # Файл с сгенерированными ключами
    DEFAULT_KEYS = [
        "АААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААА",
        "МИР",
        "ЩФЛЗАРСХГЮВКМЕЙЦЖЮБТЪЁЧЫПИЖНУЭЙДЯФЪЖЧТЬБХЦЩСШЫМЖЮЩДЪГШЭНПЕВХЧЩЫГТЯЦЙЖЩЮЭЛЬБЕФВЁХЪЧДЛИЫКР",
        "СЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТБЮШГЭТЛЦЖШЧМЙЗЦЭЪЪПЬЁШТЩЫЧЛЮДВЦЖШГФЬ",
        "МНПОМНОППМНООММНПППНПОННММОППМНННОММППМНННОПНПОМНОННМНОПМННПОМНОММПОММННПОМНОНМППМНПНПОНПННОПМ",
        "МЛПМЛОМПЛНЛПЛМЛПЛПЛМПЛНПМЛПЛНЛПМПЛПЛМПНПЛЛМППМЛПЛЛПЛНПМПЛПМЛПЛПЛЛПЛПЛПЛПМЛНЛПЛПЛППМПЛНЛПЛПМЛ",
        "БВГБАГАВДАБГГВВЕБГАБВВЕАГГБГГАЕАВГБДГВААГДЕБГААГГБЕАГГГАЕАБАААГААГБЕАГГЕБГАБГЕБАБАГААГГАЕБВААГ",
        "АЯБЮАГЩАШВЯАГЯЩАГШЮЯАЩАГЯЮАБШАГЮШЯАГЩАЯАГЮШЩАБАГЯЮАГЩАГШЯЮАГЯБАЩЮАШЯАГЩАГЮАБЩАГШЯАГЮАЩЮАГА",
        "ЦКЯФЭТЗНЙЩХБЮЕМХСЁЛДРПЮЫЪГШТЬВАЖЖШЧПСЦЖЯФЦИМЭЩЙГЖХШДЯЮОПЦЫЁГЗРЧЙЩЫЪВЖЭТЦЁСХПЮЯОКМЕФЧЛДНУЬЩЦ",
        "РСПЙООКУЖР",
        "ОФМНРУТСНО",
        "ЕГЖВЖЕБЕДВ",
        "ЦЧЩСЪЯКЫЩО",
    ]  # Стандартные ключи
    """... (комментарии о распределениях) ..."""

    if not os.path.exists(INPUT_FILE):
        print(f"Ошибка: файл {INPUT_FILE} не найден!")
        return

    # Сбор всех ключей (стандартные + из файла)
    all_keys = DEFAULT_KEYS.copy()

    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as f_keys:
                file_keys = [line.strip() for line in f_keys]
                file_keys = [k for k in file_keys if k]  # Удаление пустых ключей
                print(f"Найдено {len(file_keys)} ключей в файле {KEYS_FILE}")
                all_keys.extend(file_keys)
        except Exception as e:
            print(f"Ошибка при чтении {KEYS_FILE}: {e}")
    else:
        print(f"Файл {KEYS_FILE} не найден, используются только ключи по умолчанию")

    # Удаление дубликатов ключей
    unique_keys = []
    seen = set()
    for key in all_keys:
        if key not in seen:
            seen.add(key)
            unique_keys.append(key)

    print(f"Всего уникальных ключей для анализа: {len(unique_keys)}")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        plaintext = f.read()

    results = []

    # Сбор характеристик ключей
    key_characteristics = []
    for key in unique_keys:
        key_characteristics.append(
            {
                "key": key,
                "length": len(key),
                "entropy": calculate_entropy(key),
                "distribution": detect_key_distribution(key),
            }
        )

    for key_info in key_characteristics:
        key = key_info["key"]
        try:
            # Шифрование
            start_time = time.time()
            ciphertext = vigenere.vigenere_encrypt(plaintext, key)
            encrypt_time = time.time() - start_time

            # Атака
            start_time = time.time()
            key_length_candidates = cryptoanalysis.kasiski_examination(ciphertext)
            best_accuracy = 0
            best_found_key = ""
            best_key_length = 0
            best_decrypted = ""

            for k_len in key_length_candidates:
                found_key = cryptoanalysis.frequency_attack(ciphertext, k_len)
                decrypted = vigenere.vigenere_decrypt(ciphertext, found_key)

                # Проверка точности
                clean_plain = vigenere.clean_text(plaintext)
                clean_decrypted = vigenere.clean_text(decrypted)
                min_len = min(len(clean_plain), len(clean_decrypted))
                accuracy = (
                    sum(
                        1
                        for i in range(min_len)
                        if clean_plain[i] == clean_decrypted[i]
                    )
                    / len(clean_plain)
                    * 100
                )

                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_found_key = found_key
                    best_key_length = k_len
                    best_decrypted = decrypted

            decrypt_time = time.time() - start_time

            # Сравнение ключей
            key_accuracy = compare_keys(key, best_found_key)

            # Декрипт с оригинальным ключом для проверки
            correct_decrypted = vigenere.vigenere_decrypt(ciphertext, key)
            clean_correct = vigenere.clean_text(correct_decrypted)
            clean_original = vigenere.clean_text(plaintext)
            correct_accuracy = (
                sum(
                    1
                    for i in range(min(len(clean_original), len(clean_correct)))
                    if clean_original[i] == clean_correct[i]
                )
                / len(clean_original)
                * 100
            )

            results.append(
                {
                    "original_key": key,
                    "found_key": best_found_key,
                    "key_accuracy": key_accuracy,
                    "key_length": key_info["length"],
                    "key_entropy": key_info["entropy"],
                    "key_distribution": key_info["distribution"],
                    "encrypt_time": encrypt_time,
                    "decrypt_time": decrypt_time,
                    "text_accuracy": best_accuracy,
                    "correct_decrypt_accuracy": correct_accuracy,
                    "ciphertext": (
                        ciphertext[:100] + "..."
                        if len(ciphertext) > 100
                        else ciphertext
                    ),
                    "decrypted_with_found": (
                        best_decrypted[:100] + "..." if best_decrypted else ""
                    ),
                    "decrypted_with_original": (
                        correct_decrypted[:100] + "..." if correct_decrypted else ""
                    ),
                }
            )
        except Exception as e:
            print(f"Ошибка при обработке ключа '{key[:10]}...': {str(e)}")

    # Сохранение результатов в файл
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for i, res in enumerate(results):
            f.write(f"Тест #{i+1}\n")
            f.write(f"Исходный ключ: {res['original_key']}\n")
            f.write(f"Найденный ключ: {res['found_key']}\n")
            f.write(f"Точность ключа: {res['key_accuracy']:.2f}%\n")
            f.write(f"Длина ключа: {res['key_length']}\n")
            f.write(f"Энтропия ключа: {res['key_entropy']:.4f}\n")
            f.write(f"Тип распределения: {res['key_distribution']}\n")
            f.write(f"Время шифрования: {res['encrypt_time']:.6f} сек\n")
            f.write(f"Время атаки: {res['decrypt_time']:.6f} сек\n")
            f.write(f"Точность текста: {res['text_accuracy']:.2f}%\n")
            f.write(
                f"Точность правильного декрипта: {res['correct_decrypt_accuracy']:.2f}%\n"
            )
            f.write(f"Шифртекст (начало): {res['ciphertext']}\n")
            f.write(
                f"Расшифровано найденным ключом (начало): {res['decrypted_with_found']}\n"
            )
            f.write(
                f"Расшифровано исходным ключом (начало): {res['decrypted_with_original']}\n"
            )
            f.write("-" * 80 + "\n")

    print(f"Результаты сохранены в {OUTPUT_FILE}")

    # ================================================
    # ПОСТРОЕНИЕ ГРАФИКОВ ЗАВИСИМОСТИ ТОЧНОСТИ КЛЮЧА
    # ================================================
    if not results:
        print("Нет данных для построения графиков")
        return

    plt.figure(figsize=(15, 12))
    plt.suptitle("Анализ криптостойкости шифра Виженера", fontsize=16)

    # 1. Зависимость точности ключа от длины ключа
    plt.subplot(2, 2, 1)
    lengths = [res["key_length"] for res in results]
    key_accuracies = [res["key_accuracy"] for res in results]
    plt.scatter(lengths, key_accuracies, alpha=0.7, color="royalblue")
    plt.title("Точность восстановления ключа vs Длина ключа")
    plt.xlabel("Длина ключа (символов)")
    plt.ylabel("Точность восстановления ключа (%)")
    plt.grid(True)

    # Линия тренда
    if len(lengths) > 1:
        z = np.polyfit(lengths, key_accuracies, 1)
        p = np.poly1d(z)
        plt.plot(lengths, p(lengths), "r--")

    # 2. Зависимость точности ключа от энтропии ключа
    plt.subplot(2, 2, 2)
    entropies = [res["key_entropy"] for res in results]
    plt.scatter(entropies, key_accuracies, alpha=0.7, color="firebrick")
    plt.title("Точность восстановления ключа vs Энтропия ключа")
    plt.xlabel("Энтропия ключа (бит)")
    plt.ylabel("Точность восстановления ключа (%)")
    plt.grid(True)

    # Линия тренда
    if len(entropies) > 1:
        z = np.polyfit(entropies, key_accuracies, 1)
        p = np.poly1d(z)
        plt.plot(entropies, p(entropies), "r--")

    # 3. Зависимость от типа распределения
    plt.subplot(2, 2, 3)
    distributions = [res["key_distribution"] for res in results]

    # Группировка по типам распределения
    dist_accuracies = {}
    for dist, acc in zip(distributions, key_accuracies):
        if dist not in dist_accuracies:
            dist_accuracies[dist] = []
        dist_accuracies[dist].append(acc)

    # Подготовка данных для боксплота
    dist_types = list(dist_accuracies.keys())
    acc_data = [dist_accuracies[dist] for dist in dist_types]

    plt.boxplot(acc_data, labels=dist_types)
    plt.title("Точность восстановления ключа по типам распределения")
    plt.xlabel("Тип распределения ключа")
    plt.ylabel("Точность восстановления ключа (%)")
    plt.grid(True)

    # 4. Комбинированный график
    plt.subplot(2, 2, 4)
    colors = {
        "uniform": "blue",
        "repeating": "red",
        "other": "green",
        "unknown": "gray",
    }

    for i, dist in enumerate(distributions):
        plt.scatter(
            lengths[i],
            entropies[i],
            c=colors.get(dist, "gray"),
            s=key_accuracies[i] * 2,  # Размер точки отражает точность
            alpha=0.6,
        )

    plt.title("Комбинированная зависимость")
    plt.xlabel("Длина ключа")
    plt.ylabel("Энтропия ключа")
    plt.grid(True)

    # Создание легенды
    legend_elements = []
    for dist, color in colors.items():
        legend_elements.append(
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor=color,
                markersize=10,
                label=dist,
            )
        )

    plt.legend(handles=legend_elements, title="Типы распределения")

    plt.tight_layout(rect=[0, 0, 1, 0.96])  # Учет заголовка
    plt.savefig("crypto_strength_analysis.png", dpi=300)
    plt.close()

    print("Графики анализа криптостойкости сохранены в crypto_strength_analysis.png")


if __name__ == "__main__":
    main()
