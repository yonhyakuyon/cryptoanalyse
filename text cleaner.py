import re


def remove_punctuation(text):
    """
    Удаляет все знаки препинания из текста
    Сохраняет: русские буквы, цифры, пробелы, символы новой строки
    """
    # Регулярное выражение для удаления знаков препинания
    # Сохраняем:
    #   \w - буквы и цифры (включая русские в юникоде)
    #   \s - пробельные символы (пробелы, переносы строк и т.д.)
    pattern = r"[^\w\s]"
    return re.sub(pattern, "", text)


def main():
    # Запрос путей к файлам у пользователя
    input_file = "text.txt"
    output_file = "result_text.txt"

    try:
        # Чтение текста из файла
        with open(input_file, "r", encoding="utf-8") as f:
            text = f.read()

        # Удаление знаков препинания
        cleaned_text = remove_punctuation(text)

        # Запись результата в файл
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(cleaned_text)

        print(f"\nУспешно обработано!")
        print(f"Символов до обработки: {len(text)}")
        print(f"Символов после обработки: {len(cleaned_text)}")
        print(f"Результат сохранен в: {output_file}")

    except Exception as e:
        print(f"\nОшибка: {str(e)}")
        print("Проверьте правильность путей к файлам и их содержимое")


if __name__ == "__main__":
    main()
