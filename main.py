import telebot
import requests
import re
import base64
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from typing import Dict, List
from telebot import types
from dotenv import load_dotenv
import os

# Загрузка переменных окружения
load_dotenv()
API_TOKEN = os.getenv("API_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not API_TOKEN or not VIRUSTOTAL_API_KEY:
    raise ValueError("Не найдены необходимые переменные окружения!")

bot = telebot.TeleBot(API_TOKEN)

# Инициализация Кнопок
def create_main_keyboard():
    """Создает главную клавиатуру с кнопками."""
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    btn_check = types.KeyboardButton("🔍 Проверить сообщение/ссылку")
    btn_test = types.KeyboardButton("🎓 Пройти тест")
    markup.add(btn_check, btn_test)
    return markup

# Инициализация NLP-модели
try:
    model_name = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    nlp = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer
    )
except Exception as e:
    print(f"Ошибка загрузки модели: {e}")
    nlp = None

# Тестирование
SAFETY_QUESTIONS = [
    {
        "question": "Как злоумышленники могут получить ваш пароль, даже если сайт, которым вы пользуетесь, сам не подвергся взлому?",
        "options": [
            "Через утечку базы данных с другого сервиса, где вы использовали тот же пароль",
            "С помощью автоматического подбора паролей (Brute Force)",
            "Через фишинговые атаки и поддельные страницы входа",
            "Все перечисленное"
        ],
        "correct": 3,
        "explanation": "Все перечисленные методы могут быть использованы для кражи паролей."
    },
    {
        "question": "Каким способом можно подделать URL сайта, чтобы он выглядел как настоящий?",
        "options": [
            "Использовать поддельные сертификаты безопасности",
            "Создать домен с похожими символами (например, g00gle.com вместо google.com)",
            "Вставить вредоносный JavaScript-код в URL-адрес",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "Все перечисленные методы могут использоваться для маскировки URL."
    },
    {
        "question": "Как злоумышленники могут похитить данные вашей банковской карты без вашего ведома?",
        "options": [
            "Используя скрытые кейлоггеры или шпионское ПО",
            "Подменяя форму оплаты на зараженных сайтах",
            "Сканируя данные карты через беспроводные платежи (NFC)",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "Все эти методы представляют угрозу безопасности."
    },
    {
        "question": "Что из перечисленного является наименее надежным способом хранения паролей?",
        "options": [
            "Использование менеджера паролей с мастер-ключом",
            "Запись паролей в зашифрованный документ",
            "Запоминание всех паролей в голове",
            "Хранение всех паролей в текстовом файле на рабочем столе"
        ],
        "correct": 3,
        "explanation": "Хранение паролей в обычном текстовом файле — крайне ненадежно."
    },
    {
        "question": "Что делает злоумышленник при атаке типа Man-in-the-Middle?",
        "options": [
            "Прослушивает и изменяет передаваемые данные между вами и сайтом",
            "Использует ваш IP-адрес для анонимного серфинга в сети",
            "Встраивает вредоносную рекламу в веб-страницы",
            "Отправляет вам вредоносные письма с поддельных доменов"
        ],
        "correct": 0,
        "explanation": "Man-in-the-Middle атакующий перехватывает и может изменять данные между вами и сайтом."
    },
    {
        "question": "Какой из методов защиты наиболее эффективен против атак с перехватом трафика в публичных Wi-Fi сетях?",
        "options": [
            "Использование VPN",
            "Отключение Bluetooth и Wi-Fi, если они не используются",
            "Избегание ввода личных данных при подключении к открытым сетям",
            "Все вышеперечисленное"
        ],
        "correct": 3,
        "explanation": "Все эти меры увеличивают вашу безопасность в открытых сетях."
    },
    {
        "question": "Вы скачиваете файл с популярного сайта, но перед этим видите предупреждение от браузера, что он может быть небезопасным. Какие действия следует предпринять?",
        "options": [
            "Игнорировать предупреждение и скачать файл, если он от известного разработчика",
            "Проверить цифровую подпись файла и сверить хеш-сумму с оригиналом",
            "Открыть файл на виртуальной машине или в песочнице (sandbox)",
            "Варианты b и c"
        ],
        "correct": 3,
        "explanation": "Проверка подписи и использование sandbox — безопасный подход."
    },
    {
        "question": "Какой из приведенных сценариев указывает на возможную атаку социальной инженерии?",
        "options": [
            "Вы получаете звонок от «банковского сотрудника», который просит подтвердить перевод, которого вы не совершали",
            "Вам приходит письмо с вложением, якобы от вашего коллеги, но с необычным текстом",
            "Незнакомец в социальных сетях просит вас помочь ему восстановить доступ к его аккаунту",
            "Все вышеперечисленные ситуации"
        ],
        "correct": 3,
        "explanation": "Все эти примеры — типичные атаки социальной инженерии."
    },
    {
        "question": "Какой способ защиты наиболее эффективен для предотвращения утечки данных в случае компрометации вашего пароля?",
        "options": [
            "Использование уникальных паролей для каждого сервиса",
            "Включение двухфакторной аутентификации (2FA)",
            "Регулярная проверка своих данных на утечки",
            "Все вышеперечисленные методы"
        ],
        "correct": 3,
        "explanation": "Комплексный подход — лучшая защита."
    }
]

user_progress = {}


# Вспомогательные функции
def encode_url(url: str) -> str:
    """Кодирование URL для VirusTotal"""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_url_virustotal(url: str) -> Dict:
    """Проверка URL через VirusTotal API с улучшенной обработкой ошибок"""
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        report_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'

        response = requests.get(report_url, headers=headers, timeout=10)
        print(f"VirusTotal API Response: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0)
            }

        elif response.status_code == 404:
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            response = requests.post(
                scan_url,
                headers=headers,
                data={'url': url},
                timeout=15
            )
            if response.status_code == 200:
                return {'status': 'queued', 'message': 'URL отправлен на анализ. Повторите проверку через 2 минуты.'}
            else:
                return {'error': f"Ошибка отправки на сканирование: {response.status_code}"}
                
        elif response.status_code == 429:
            return {'error': 'Превышен лимит запросов к VirusTotal. Попробуйте позже.'}

        else:
            return {'error': f'Неизвестная ошибка API: {response.status_code}'}
                   
    except requests.exceptions.RequestException as e:
        return {'error': f"Ошибка сети: {str(e)}"}
        
    except Exception as e:
        return {'error': f"Неизвестная ошибка: {str(e)}"}

def analyze_text(text: str) -> Dict:
    """Анализ текста на фишинг с помощью NLP"""
    try:
        if not nlp:
            return {'error': 'Модель не загружена'}

        tokenized_input = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        truncated_text = tokenizer.decode(tokenized_input["input_ids"][0], skip_special_tokens=True)

        result = nlp(truncated_text)[0]
        print(f"NLP Result: {result}")

        phishing_keywords = {}
        text_lower = text.lower()
        found_keywords = {
            keyword for keyword in phishing_keywords
            if re.search(rf'\b{re.escape(keyword)}\w*\b', text_lower)
        }

        return {
            'label': 'phishing' if result['label'] == 'LABEL_1' else 'safe',
            'score': result['score'],
            'keywords': list(found_keywords)
        }

    except Exception as e:
        print(f"NLP Analysis Error: {e}")
        return {'error': str(e)}

def perform_analysis(message):
    """Выполняет анализ текста и URL из сообщения."""
    try:
        text = message.text
        report = []
        print(f"Processing message for analysis: {text}")

        urls = re.findall(r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+', text)
        expanded_urls = []
        if urls:
            report.append("🔎 Анализ ссылок:")
            for url in urls:
                if not url.startswith(('http://', 'https://', 'ftp://')):
                    url = 'http://' + url
                try:
                    response = requests.get(
                        url,
                        allow_redirects=True, 
                        timeout=7,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    expanded = response.url
                    if expanded != url and len(expanded) > len(url) + 5:
                        report.append(f"🔗 Сокращенная ссылка: `{url}` -> `{expanded}`")
                    expanded_urls.append(expanded)
                except requests.exceptions.RequestException as e:
                    print(f"Ошибка раскрытия URL {url}: {str(e)}")
                    report.append(f"⚠️ Не удалось проверить ссылку: `{url}` (Ошибка: {type(e).__name__})")
                    if url not in expanded_urls:
                         expanded_urls.append(url)
                except Exception as e:
                     print(f"Неизвестная ошибка при обработке URL {url}: {str(e)}")
                     report.append(f"⚠️ Не удалось проверить ссылку: `{url}` (Неизвестная ошибка)")
                     if url not in expanded_urls:
                         expanded_urls.append(url)


            for url_to_check in expanded_urls:
                vt_result = check_url_virustotal(url_to_check)
                print(f"VirusTotal Result for {url_to_check}: {vt_result}")

                if vt_result.get('error'):
                    report.append(f"    - `{url_to_check}`: Ошибка VirusTotal ({vt_result['error']})")
                elif vt_result.get('status') == 'queued':
                     report.append(f"    - `{url_to_check}`: ⏳ Отправлен на анализ VT. Повторите через 1-2 мин.")
                elif vt_result.get('malicious', 0) > 1 or vt_result.get('suspicious', 0) > 1:
                    report.append(
                        f"    - `{url_to_check}`: 🔴 Опасно (VT: M:{vt_result['malicious']}, S:{vt_result['suspicious']}, H:{vt_result['harmless']})"
                    )
                elif vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0:
                     report.append(
                        f"    - `{url_to_check}`: 🟡 Подозрительно (VT: M:{vt_result['malicious']}, S:{vt_result['suspicious']}, H:{vt_result['harmless']})"
                    )
                else:
                    report.append(
                        f"    - `{url_to_check}`: ✅ Безопасно (VT: M:{vt_result['malicious']}, S:{vt_result['suspicious']}, H:{vt_result['harmless']})"
                    )
        else:
             report.append("ℹ️ Ссылки в сообщении не найдены.")


        if nlp:
            report.append("\n📝 Анализ текста:")
            text_result = analyze_text(text)
            if text_result.get('error'):
                 report.append(f"    - Ошибка анализа текста: {text_result['error']}")
            elif text_result.get('label') == 'phishing' and text_result.get('score', 0) > 0.6:
                report.append(
                    f"    - 🟡 Подозрительный текст (уверенность: {text_result['score']:.0%})"
                )
                if text_result.get('keywords'):
                    report.append(f"      Найденные ключевые слова: `{', '.join(text_result['keywords'])}`")
            else:
                 report.append("    - ✅ Текст не выглядит подозрительным.")
        else:
             report.append("\n⚠️ Модель анализа текста не загружена, проверка текста не выполнена.")


        if report:
            bot.reply_to(message, "\n".join(report), parse_mode="Markdown")

    except Exception as e:
        print(f"Error in perform_analysis: {e}")
        bot.reply_to(message, f"❌ Произошла внутренняя ошибка при анализе: {str(e)}")

# Обработчики команд
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """Приветственное сообщение и показ кнопок"""
    help_text = """
👋 Привет! Я антифишинговый бот.

🛡️ Мои возможности:
- Проверка сообщений: Анализирую текст и ссылки на фишинг и вредоносность с помощью NLP и VirusTotal.
- Тест безопасности: Проверь свои знания о цифровых угрозах.

👇 Используй кнопки ниже
"""
    image_path = 'cat.jpg'
    try:
        with open(image_path, 'rb') as photo_file:
            # Отправляем фото с текстом в качестве подписи и прикрепляем клавиатуру
            bot.send_photo(
                chat_id=message.chat.id,
                photo=photo_file,
                caption=help_text,
                reply_markup=create_main_keyboard()
            )
    except FileNotFoundError:
        print(f"Ошибка: Файл картинки не найден по пути {image_path}")
        # Если файл не найден, отправляем только текст и кнопки
        bot.send_message(
            message.chat.id,
            help_text + "\n\n(Не удалось загрузить приветственное изображение)",
            reply_markup=create_main_keyboard()
        )
    except Exception as e:
        print(f"Произошла ошибка при отправке фото: {e}")
        # Обработка других возможных ошибок при отправке
        bot.send_message(
            message.chat.id,
            "Произошла ошибка при отображении приветствия.",
            reply_markup=create_main_keyboard()
        )


@bot.message_handler(commands=['safety_test'])
def start_safety_test_command(message):
    """Запуск теста через команду"""
    start_safety_test(message)

def start_safety_test(message):
    """Начало теста"""
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_progress[user_id] = {"current_question": 0, "score": 0}
    bot.send_message(chat_id, "Начинаем тест! Выберите правильный вариант ответа.", reply_markup=types.ReplyKeyboardRemove())
    ask_question(chat_id, user_id)


def ask_question(chat_id: int, user_id: int):
    """Отправка вопроса с вариантами ответов (Inline кнопки)"""
    if user_id not in user_progress:
        bot.send_message(chat_id, "Произошла ошибка с тестом. Пожалуйста, начните заново.", reply_markup=create_main_keyboard())
        return

    current_q_index = user_progress[user_id]["current_question"]
    if current_q_index >= len(SAFETY_QUESTIONS):
        finalize_test(chat_id, user_id)
        return

    markup = types.InlineKeyboardMarkup(row_width=1)
    question_data = SAFETY_QUESTIONS[current_q_index]

    for idx, option in enumerate(question_data["options"]):
        markup.add(types.InlineKeyboardButton(
            text=option,
            callback_data=f"answer_{current_q_index}_{idx}"
        ))

    bot.send_message(
        chat_id,
        f"Вопрос {current_q_index + 1}/{len(SAFETY_QUESTIONS)}\n\n" +
        question_data["question"],
        reply_markup=markup,
        parse_mode="Markdown"
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith('answer_'))
def handle_answer(call):
    """Обработка ответов на вопросы теста"""
    user_id = call.from_user.id
    chat_id = call.message.chat.id

    if user_id not in user_progress:
        bot.answer_callback_query(call.id, "Тест не найден для вас. Возможно, бот перезапускался.")
        bot.edit_message_text(
            chat_id=chat_id,
            message_id=call.message.message_id,
            text="Произошла ошибка. Пожалуйста, начните тест заново.",
            reply_markup=None
        )
        bot.send_message(chat_id, "Вы можете продолжить использовать другие функции.", reply_markup=create_main_keyboard())
        return

    try:
        _, q_idx_str, a_idx_str = call.data.split('_')
        q_idx = int(q_idx_str)
        a_idx = int(a_idx_str)
    except ValueError:
        print(f"Ошибка парсинга callback_data: {call.data}")
        bot.answer_callback_query(call.id, "Ошибка обработки ответа.")
        return

    if q_idx != user_progress[user_id]["current_question"]:
        bot.answer_callback_query(call.id, "Это ответ на предыдущий вопрос.")
        return

    question = SAFETY_QUESTIONS[q_idx]
    is_correct = (a_idx == question["correct"])

    if is_correct:
        user_progress[user_id]["score"] += 1
        result_text = "✅ Правильно!\n\n"
    else:
        result_text = f"❌ Неверно. Правильный ответ: {question['options'][question['correct']]}\n\n"

    bot.edit_message_text(
        chat_id=chat_id,
        message_id=call.message.message_id,
        text=f"Вопрос {q_idx + 1}: {question['question']}\n\n" +
             f"Ваш ответ: {question['options'][a_idx]}\n\n" +
             result_text +
             f"Пояснение: {question['explanation']}",
        reply_markup=None,
        parse_mode="Markdown"
    )
    bot.answer_callback_query(call.id)

    user_progress[user_id]["current_question"] += 1
    if user_progress[user_id]["current_question"] < len(SAFETY_QUESTIONS):
        ask_question(chat_id, user_id)
    else:
        finalize_test(chat_id, user_id)

def finalize_test(chat_id: int, user_id: int):
    """Завершение теста и вывод результатов"""
    if user_id not in user_progress: return

    score = user_progress[user_id]["score"]
    total = len(SAFETY_QUESTIONS)
    percentage = (score / total) * 100 if total > 0 else 0

    feedback = ""
    if percentage == 100:
        feedback = "🎉 Отличный результат! Вы прекрасно осведомлены об основах безопасности!"
    elif percentage >= 70:
        feedback = f"👍 Хороший результат ({percentage:.0f}%)! Вы неплохо разбираетесь, но всегда есть что улучшить."
    elif percentage >= 40:
        feedback = f"⚠️ Неплохо ({percentage:.0f}%), но стоит подтянуть знания, чтобы лучше защитить себя."
    else:
        feedback = f"😥 Низкий результат ({percentage:.0f}%). Рекомендую изучить материалы по цифровой безопасности."

    recommendations_header = "\n\n📌 Ключевые правила безопасности:"
    recommendations = [
        "1. Используйте сложные и уникальные пароли для каждого сервиса.",
        "2. Включайте двухфакторную аутентификацию (2FA) везде, где возможно.",
        "3. Будьте подозрительны к неожиданным письмам, сообщениям и звонкам, особенно если просят личные данные или деньги.",
        "4. Проверяйте адреса ссылок перед переходом, особенно в подозрительных сообщениях.",
        "5. Не скачивайте файлы из ненадежных источников.",
        "6. Используйте VPN при подключении к общественным Wi-Fi сетям.",
        "7. Регулярно обновляйте ПО и операционную систему.",
        "8. Узнайте больше о фишинге и социальной инженерии."
    ]

    final_message = (
        f"🏁 Тест завершен!\n\n"
        f"Правильных ответов: {score} из {total}\n\n"
        f"{feedback}\n"
        f"{recommendations_header}\n" +
        "\n".join(recommendations) +
        "\n\n🔗 *Подробнее об онлайн-безопасности можно узнать на сайтах экспертов, например, Kaspersky или ESET.*"
    )

    bot.send_message(
        chat_id,
        final_message,
        reply_markup=create_main_keyboard(),
        parse_mode="Markdown"
    )

    if user_id in user_progress:
        del user_progress[user_id]


@bot.message_handler(commands=['check'])
def handle_check_command(message):
    """Обработчик команды /check [текст]"""
    try:
        text_to_check = message.text.split(None, 1)[1]
        if text_to_check:
            fake_message = types.Message(
                message_id=message.message_id,
                from_user=message.from_user,
                date=message.date,
                chat=message.chat,
                content_type='text',
                options={},
                json_string=""
            )
            fake_message.text = text_to_check
            perform_analysis(fake_message)
        else:
            bot.reply_to(message, "Пожалуйста, укажите текст или ссылку после команды /check для проверки.")
    except IndexError:
         bot.reply_to(message, "Пожалуйста, укажите текст или ссылку после команды /check для проверки.")
    except Exception as e:
        print(f"Error in /check handler: {e}")
        bot.reply_to(message, f"❌ Ошибка при обработке команды /check: {str(e)}")


@bot.message_handler(content_types=['text'])
def handle_message(message):
    """Основной обработчик текстовых сообщений и кнопок"""
    user_id = message.from_user.id
    text = message.text

    if text == "🔍 Проверить сообщение/ссылку":
        bot.reply_to(message, "Хорошо, отправьте мне сообщение, которое нужно проверить.")
    elif text == "🎓 Пройти тест безопасности":
        start_safety_test(message)
    elif not text.startswith('/'):
        perform_analysis(message)


if __name__ == "__main__":
    print("Бот запущен...")
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        print(f"Ошибка polling: {e}")
