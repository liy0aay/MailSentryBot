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
        "question": "1. Как злоумышленники могут получить ваш пароль, даже если сайт, которым вы пользуетесь, сам не подвергся взлому?",
        "options": [
            "Через утечку базы данных с другого сервиса, где вы использовали тот же пароль",
            "С помощью автоматического подбора паролей (Brute Force)",
            "Через фишинговые атаки и поддельные страницы входа",
            "Все перечисленное"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Все перечисленные методы могут быть использованы для кражи паролей."
    },
    {
        "question": "2. Каким способом можно подделать URL сайта, чтобы он выглядел как настоящий?",
        "options": [
            "Использовать поддельные сертификаты безопасности",
            "Создать домен с похожими символами (например, g00gle.com вместо google.com)",
            "Вставить вредоносный JavaScript-код в URL-адрес",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Все перечисленные методы могут использоваться для маскировки URL."
    },
    {
        "question": "3. Как злоумышленники могут похитить данные вашей банковской карты без вашего ведома?",
        "options": [
            "Используя скрытые кейлоггеры или шпионское ПО",
            "Подменяя форму оплаты на зараженных сайтах",
            "Сканируя данные карты через беспроводные платежи (NFC)",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Все эти методы представляют угрозу безопасности."
    },
    {
        "question": "4. Что из перечисленного является наименее надежным способом хранения паролей?",
        "options": [
            "Использование менеджера паролей с мастер-ключом",
            "Запись паролей в зашифрованный документ",
            "Запоминание всех паролей в голове",
            "Хранение всех паролей в текстовом файле на рабочем столе"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Хранение паролей в обычном текстовом файле — крайне ненадежно."
    },
    {
        "question": "5. Что делает злоумышленник при атаке типа Man-in-the-Middle?",
        "options": [
            "Прослушивает и изменяет передаваемые данные между вами и сайтом",
            "Использует ваш IP-адрес для анонимного серфинга в сети",
            "Встраивает вредоносную рекламу в веб-страницы",
            "Отправляет вам вредоносные письма с поддельных доменов"
        ],
        "correct": 0,
        "explanation": "✅ Верно! Man-in-the-Middle атакующий перехватывает и может изменять данные между вами и сайтом."
    },
    {
        "question": "6. Какой из методов защиты наиболее эффективен против атак с перехватом трафика в публичных Wi-Fi сетях?",
        "options": [
            "Использование VPN",
            "Отключение Bluetooth и Wi-Fi, если они не используются",
            "Избегание ввода личных данных при подключении к открытым сетям",
            "Все вышеперечисленное"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Все эти меры увеличивают вашу безопасность в открытых сетях."
    },
    {
        "question": "7. Вы скачиваете файл с популярного сайта, но перед этим видите предупреждение от браузера, что он может быть небезопасным. Какие действия следует предпринять?",
        "options": [
            "Игнорировать предупреждение и скачать файл, если он от известного разработчика",
            "Проверить цифровую подпись файла и сверить хеш-сумму с оригиналом",
            "Открыть файл на виртуальной машине или в песочнице (sandbox)",
            "Варианты b и c"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Проверка подписи и использование sandbox — безопасный подход."
    },
    {
        "question": "8. Какой из приведенных сценариев указывает на возможную атаку социальной инженерии?",
        "options": [
            "Вы получаете звонок от «банковского сотрудника», который просит подтвердить перевод, которого вы не совершали",
            "Вам приходит письмо с вложением, якобы от вашего коллеги, но с необычным текстом",
            "Незнакомец в социальных сетях просит вас помочь ему восстановить доступ к его аккаунту",
            "Все вышеперечисленные ситуации"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Все эти примеры — типичные атаки социальной инженерии."
    },
    {
        "question": "9. Какой способ защиты наиболее эффективен для предотвращения утечки данных в случае компрометации вашего пароля?",
        "options": [
            "Использование уникальных паролей для каждого сервиса",
            "Включение двухфакторной аутентификации (2FA)",
            "Регулярная проверка своих данных на утечки",
            "Все вышеперечисленные методы"
        ],
        "correct": 3,
        "explanation": "✅ Верно! Комплексный подход — лучшая защита."
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
        # Кодирование URL с обработкой спецсимволов
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
        
        response = requests.get(report_url, headers=headers, timeout=10)
        print(f"VirusTotal API Response: {response.status_code}")  # Логирование

        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0)
            }

        # Если отчет не найден, отправляем URL на сканирование
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

        return {'error': f"Ошибка API: {response.status_code}"}

    except Exception as e:
        print(f"VirusTotal Error: {str(e)}")  # Логирование ошибок
        return {'error': f"Ошибка подключения: {str(e)}"}


def analyze_text(text: str) -> Dict:
    """Анализ текста на фишинг с помощью NLP"""
    try:
        if not nlp:
            return {'error': 'Модель не загружена'}
            
        result = nlp(text[:512])[0]
        print(f"NLP Result: {result}")

        phishing_keywords = {
            'розыгрыш', 'приз', 'победитель', 'подарок', 'коробка', 'бесплатно',
            'банк', 'карта', 'пароль', 'срочно', 'уведомление', 'дозвониться',
            'маркетплейс', 'акция', 'выигрыш', 'подтвердить', 'безопасность',
            'winner', 'prize', 'urgent', 'security', 'verify', 'account'
        }
        
        # Поиск ключевых слов с учетом морфологии
        text_lower = text.lower()
        found_keywords = {
            keyword for keyword in phishing_keywords
            if re.search(rf'\b{re.escape(keyword)}\b', text_lower)
        }

        return {
            'label': 'phishing' if result['label'] == 'LABEL_1' else 'safe',
            'score': result['score'],
            'keywords': list(found_keywords)
        }
    
    except Exception as e:
        return {'error': str(e)}


# Обработчики команд
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """Приветственное сообщение"""
    help_text = """
🔍 Я антифишинговый бот! Проверю:
- Ссылки через VirusTotal
- Текст на подозрительные фразы
- Даю рекомендации по безопасности

Команды:
/safety_test - Тест на основы безопасности
/check [текст] - Проверить сообщение
"""
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['safety_test'])
def start_safety_test(message):
    """Начало теста"""
    user_id = message.from_user.id
    user_progress[user_id] = {"current_question": 0, "correct": 0}
    ask_question(message.chat.id, user_id)

def ask_question(chat_id: int, user_id: int):
    """Отправка вопроса с вариантами ответов"""
    markup = types.InlineKeyboardMarkup()
    question_data = SAFETY_QUESTIONS[user_progress[user_id]["current_question"]]
    
    for idx, option in enumerate(question_data["options"]):
        markup.add(types.InlineKeyboardButton(
            text=option,
            callback_data=f"answer_{user_progress[user_id]['current_question']}_{idx}"
        ))
    
    bot.send_message(
        chat_id,
        f"Вопрос {user_progress[user_id]['current_question']+1}/{len(SAFETY_QUESTIONS)}\n\n" +
        question_data["question"],
        reply_markup=markup
    )

@bot.callback_query_handler(func=lambda call: call.data.startswith('answer_'))
def handle_answer(call):
    """Обработка ответов на вопросы"""
    user_id = call.from_user.id
    if user_id not in user_progress:
        return
    
    _, q_idx, a_idx = call.data.split('_')
    q_idx = int(q_idx)
    a_idx = int(a_idx)
    
    question = SAFETY_QUESTIONS[q_idx]
    
    if a_idx == question["correct"]:
        user_progress[user_id]["correct"] += 1
        result = "✅ Правильно!\n"
    else:
        result = "❌ Неверно!\n"
    
    bot.edit_message_text(
        chat_id=call.message.chat.id,
        message_id=call.message.message_id,
        text=result + question["explanation"]
    )
    
    user_progress[user_id]["current_question"] += 1
    
    if user_progress[user_id]["current_question"] < len(SAFETY_QUESTIONS):
        ask_question(call.message.chat.id, user_id)
    else:
        correct = user_progress[user_id]["correct"]
        total = len(SAFETY_QUESTIONS)
        score = correct / total
        
        feedback = (
            "🎉 Отличный результат!" if score == 1 else
            "👍 Хорошо, но есть куда расти:" if score >= 0.7 else
            "⚠️ Нужно подтянуть знания:"
        )
        
        recommendations = [
            "🧠 1. Будьте внимательны к письмам и сообщениям",
            "🌐 2. Проверяйте подлинность сайтов",
            "🧰 3. Используйте менеджеры паролей и уникальные пароли",
            "🔑 4. Всегда включайте двухфакторную аутентификацию (2FA)",
            "☠️ 5. Не скачивайте файлы с подозрительных источников",
            "📶 6. Избегайте работы с конфиденциальными данными в публичных Wi-Fi сетях",
            "👀 7. Следите за признаками социальной инженерии",
            "🧼 8. Соблюдайте цифровую гигиену"
        ]
        
        bot.send_message(
            call.message.chat.id,
            f"Тест завершен!\nПравильных ответов: {correct}/{total}\n\n{feedback}\n" + 
            "\n".join(recommendations) + 
            "\n\nПодробнее: https://www.kaspersky.ru/resource-center/preemptive-safety/top-10-preemptive-safety-rules-and-what-not-to-do-online"
        )
        del user_progress[user_id]

@bot.message_handler(func=lambda message: True)
def handle_message(message):
    """Основной обработчик сообщений"""
    try:
        text = message.text
        report = []
        print(f"Processing message: {text}")

        # 1. Проверка и раскрытие ссылок
        urls = re.findall(r'http*://*', text)
        expanded_urls = []
        for url in urls:
            try:
                # Раскрытие сокращенных URL
                expanded = requests.head(url, allow_redirects=True, timeout=5).url
                if expanded != url:
                    report.append(f"🔍 Сокращенная ссылка: {url} -> {expanded}")
                expanded_urls.append(expanded)
            except Exception as e:
                print(f"Ошибка раскрытия URL: {str(e)}")
                expanded_urls.append(url)

        # 2. Проверка через VirusTotal
        for url in expanded_urls:
            vt_result = check_url_virustotal(url)
            print(f"VirusTotal Result: {vt_result}")
            
            if 'malicious' in vt_result and vt_result['malicious'] > 0:
                report.append(
                    f"\n🔴 Опасная ссылка: {url}\n"
                    f"┣ Безопасно: {vt_result['harmless']}\n"
                    f"┣ Подозрительно: {vt_result['suspicious']}\n"
                    f"┗ Опасность: {vt_result['malicious']}"
                )

        # 3. Анализ текста через NLP
        text_result = analyze_text(text)
        if text_result.get('label') == 'phishing' and text_result.get('score', 0) > 0.4:
            report.append(
                f"\n🟡 Подозрительный текст\n"
                f"┣ Уверенность: {text_result['score']:.0%}\n"
                # f"┗ Ключевые слова: {', '.join(text_result.get('keywords', []))}"
            )

        # 4. Формирование отчета
        if report:
            bot.reply_to(message, "\n".join(report))
            print(expanded_urls)
        else:
            bot.reply_to(message, "✅ Сообщение безопасно")
            print(expanded_urls)

    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка: {str(e)}")

if __name__ == "__main__":
    print("Бот запущен...")
    bot.polling(none_stop=True)
    
