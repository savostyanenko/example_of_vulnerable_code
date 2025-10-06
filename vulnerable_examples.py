"""
vulnerable_examples.py

Файл з навчальними прикладами вразливого коду (Django/Python).
ПІДКАЗКА: виправлення наведені закоментованими рядками під кожним прикладом.
Не зберігай цей файл у продакшн і не коміти реальні секрети.
"""

# ----------------------------------------
# 1) SQL-інʼєкція (небезпечний raw SQL / конкатенація)
# ----------------------------------------
def search_vulnerable(request, MyModel):
    q = request.GET.get("q", "")
    rows = MyModel.objects.raw(f"SELECT * FROM myapp_mymodel WHERE name LIKE '%{q}%'")
    return rows

# ВИПРАВЛЕННЯ (раскоментувати замість уразливого коду):
# def search_safe(request, MyModel):
#     q = request.GET.get("q", "")
#     # Безпечніше: використовувати ORM (фільтрація автоматично екранізує)
#     rows = MyModel.objects.filter(name__icontains=q)
#     return rows
#
# # Якщо дійсно потрібен raw SQL — використовувати параметризований запит:
# from django.db import connection
# def search_safe_raw(request):
#     q = request.GET.get("q", "")
#     with connection.cursor() as c:
#         c.execute("SELECT * FROM myapp_mymodel WHERE name LIKE %s", [f"%{q}%"])
#         rows = c.fetchall()
#     return rows


# ----------------------------------------
# 2) XSS — небезпечне рендерення HTML (mark_safe / |safe)
# ----------------------------------------
def save_comment_vulnerable(request, CommentModel):
    user_input = request.POST.get("comment", "")
    # НЕБЕЗПЕЧНО: зберігаємо HTML як є і потім рендеримо як безпечний
    comment = CommentModel()
    comment.html = user_input
    comment.save()
    return comment

# Приклад шаблону (unsafe):
# {{ comment.html|safe }}    <!-- Рендерить HTML без екранування — ризик XSS -->

# ВИПРАВЛЕННЯ:
# def save_comment_safe(request, CommentModel):
#     user_input = request.POST.get("comment", "")
#     # Зберігаємо сирий текст, дозволяємо шаблону екранувати його
#     comment = CommentModel()
#     comment.text = user_input
#     comment.save()
#     return comment
#
# # Якщо потрібно дозволити обмежений HTML — слід пропустити через sanitizer (наприклад bleach):
# # from bleach import clean
# # safe_html = clean(user_input, tags=['b','i','a'], attributes={'a': ['href']})
# # comment.html = safe_html


# ----------------------------------------
# 3) Командна інʼєкція (os.system з конкатенацією)
# ----------------------------------------
import os
def backup_vulnerable(request):
    filename = request.GET.get("file", "")
    # НЕБЕЗПЕЧНО: виклик shell-команди з інтерполяцією — можливість виконання довільного коду
    os.system(f"tar -czf /backup/{filename}.tar.gz /data/{filename}")
    return "ok"

# ВИПРАВЛЕННЯ:
# import subprocess
# def backup_safe(request):
#     filename = request.GET.get("file", "")
#     # Обмежити/перевірити ім'я файлу
#     safe_name = os.path.basename(filename)
#     # Викликати без shell, передавати аргументи як список
#     subprocess.run(["tar", "-czf", f"/backup/{safe_name}.tar.gz", f"/data/{safe_name}"], check=True)
#     return "ok"


# ----------------------------------------
# 4) Небезпечна десеріалізація (pickle.loads)
# ----------------------------------------
import pickle
def load_object_vulnerable(uploaded_file):
    data = uploaded_file.read()
    # НЕБЕЗПЕЧНО: pickle.loads може виконувати код під час десеріалізації
    obj = pickle.loads(data)
    return obj

# ВИПРАВЛЕННЯ:
# import json
# def load_object_safe(uploaded_file):
#     data = uploaded_file.read()
#     # Використовувати безпечні формати (JSON) або перевірені формати
#     obj = json.loads(data.decode('utf-8'))
#     return obj
#
# # Якщо потрібно десеріалізувати складні об'єкти — застосовувати строго контрольований/визначений формат
# # або використовувати бібліотеки, які надають безпечну десеріалізацію.


# ----------------------------------------
# 5) Хардкод-секрети і DEBUG=True
# ----------------------------------------
# НЕБЕЗПЕЧНО: Дуже хардкорний хардкор секретного ключа та DEBUG=True
SECRET_KEY = "super-secret-key-123"
DEBUG = True

# ВИПРАВЛЕННЯ:
# import os
# SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "fallback-if-needed")
# DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
# # У продакшн: ніколи не зберігати секрети у репозиторії; використовувати secret manager або змінні оточення.


# ----------------------------------------
# 6) Відключення CSRF (csrf_exempt)
# ----------------------------------------
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update_profile_vulnerable(request):
    # НЕБЕЗПЕЧНО: дозволяє виконувати POST без CSRF-токена
    # (просто приклад — реальна логіка опущена)
    return "profile updated"

# ВИПРАВЛЕННЯ:
# # Не використовувати csrf_exempt без вагомої причини.
# # Якщо це API — застосовувати авторизацію (Token, JWT) і використовувати DRF з відповідними захисними механізмами.
# from django.views.decorators.csrf import csrf_protect
# @csrf_protect
# def update_profile_safe(request):
#     # валідна логіка з перевірками
#     return "profile updated"

# ----------------------------------------
# Кінець файлу
# ----------------------------------------

def get_user_data(username):
  """
  Знаходить дані користувача в базі даних за його іменем.
  !!! Ця функція вразлива до SQL-ін'єкції !!!
  """
  db = sqlite3.connect("users.db")
  cursor = db.cursor()
  
  # Вразливість знаходиться тут:
  # Ім'я користувача (username) напряму вставляється в SQL-запит.
  query = "SELECT * FROM users WHERE username = '" + username + "'"
  
  cursor.execute(query)
  user_data = cursor.fetchall()
  db.close()
  
  return user_data

# Приклад небезпечного виклику:
# Зловмисник може передати такий рядок замість імені:
# ' OR 1=1 --
#
# В результаті кінцевий запит буде виглядати так:
# SELECT * FROM users WHERE username = '' OR 1=1 --'
#
# Цей запит поверне ВСІХ користувачів з таблиці, оскільки "1=1" завжди істинне.
malicious_input = "' OR 1=1 --"
get_user_data(malicious_input)

#----------------------------------------------------
def calculate_expression(expression):
    """
    Обчислює математичний вираз, переданий як рядок.
    ⚠️ Небезпечно: використовує eval(), тому може виконати довільний код.
    """
    try:
        result = eval(expression)
        print(f"Результат: {result}")
        return result
    except Exception as e:
        print(f"Помилка: {e}")
        return None

# Приклад використання:
calculate_expression("2 + 3 * 4")
