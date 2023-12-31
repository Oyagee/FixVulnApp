# FixVulnApp
Уязвимое приложение, которое включает в себя следующие уязвимости: XSS, IDOR, SQL Injection, OS command injection, Path Traversal, Brute Force. Уязвимости исправлены.

### Инструкция по сборке и запуску приложения
1. git clone https://github.com/Oyagee/FixVulnApp.git
2. pip install -r .\requirements.txt
3. python main.py

## Комментарии к исправлениям

# XSS

Для защиты от XSS я использую функцию escape библиотеки html для экранирования ввода
Таким образом символы <, >, & преобразуются в безопасные последовательности символов

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/9549af09-c1d0-4bb7-9a89-16d63f83690a)

---

# SQL Injection

Основная идея защиты от SQL Injection заключается в использовании параметризованного запроса с заполнителями "?", а значения переменных передаются в execute() в качестве параметров. Это позволяет предотвратить возможность SQL Injection через пользовательский ввод.

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/c530df64-cada-49e3-97ef-8d015d5d9b5f)

---

# IDOR

IDOR можно исправить путем внедрения аутентификации/авторизации

В моем случае я сделал простое изменение auth_id, который сверяется с user_id и если они совпадают, то страница выводится

Если нет, то пересылает на "/"

Доступ к первому профилю есть:

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/9e49878e-3fce-43d2-bdf4-c60d58fdf234)

А при попытке перехода ко второму профилю пересылает на "/"

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/29d138a2-3396-4847-9a4a-a59ee3ec4e94)

---

# OS command injection

Для защиты от этой уязвимости я использую библиотеку лексического анализа.

С помощью split() разделяется команда на аргументы. Затем передаются в check_output() с установленным shell=False.
Это предотвращает выполнение команды через оболочку ОС.

Попытка использовать команду dir /b

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/b5b81af8-98a5-4fd5-a96c-ce2f9773883a)

---

# Path Traversal
Основная идея защиты от Path Traversal заключается в удалении всех символов, кроме букв, цифр, точек и подчеркиваний и проверки что вводимый путь находится внутри папки "uploads", в которой файлы смотреть можно

При попытке перейти на путь ../main.py

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/196f6578-bdc5-484f-bf70-0510bd35246c)


---

# Brute Force
Основная идея защиты от Brute Force заключается в добавлении количества попыток ввода и счетчика в течении которого попытки обновляются

После 5 попыток используется код ответа HTTP 429 Too Many Requests

Также возможно использовать CAPTCHA и сделать минимальные требования пароля при регистрации, чтобы его было сложно забрутить

Если было более пяти попыток входа:

![image](https://github.com/Oyagee/FixVulnApp/assets/73120241/820ed8b0-7905-46a9-afe8-7736077f5e4c)






