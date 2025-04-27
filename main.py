import telebot
import requests
import re
import base64
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from typing import Dict, List
from telebot import types
from dotenv import load_dotenv
import os
from safety_test import init_safety_test_handlers

# Загрузка переменных окружения.

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

# Инициализация Кнопок
def create_main_keyboard():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    btn_check = types.KeyboardButton("🔍 Проверить сообщение/ссылку")
    btn_test = types.KeyboardButton("🎓 Пройти тест")
    markup.add(btn_check, btn_test)
    return markup

user_progress = {}

# Инициализация обработчиков теста безопасности
init_safety_test_handlers(bot, user_progress, create_main_keyboard)

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
                'harmless': stats.get('harmless', 0),
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

        return {
            'label': 'phishing' if result['label'] == 'LABEL_1' else 'safe',
            'score': result['score'],
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

        urls = re.findall(r'(?:(?:https?|ftp):\/\/)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?', text)
        
        if urls:
            report.append("🔎 Анализ ссылок:")
            for original_url in urls:
                url_to_check = original_url if original_url.startswith(('http://', 'https://', 'ftp://')) else 'http://' + original_url
                try:
                    response = requests.get(
                        url_to_check,
                        allow_redirects=True, 
                        timeout=7,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    expanded_url = response.url

                    vt_result = check_url_virustotal(expanded_url)
                    print(f"VirusTotal Result for {expanded_url}: {vt_result}")
    
                    if vt_result.get('error'):
                        report.append(f"    - `{original_url}`: Ошибка VirusTotal ({vt_result['error']})")
                    elif vt_result.get('status') == 'queued':
                         report.append(f"    - `{original_url}`: ⏳ Отправлен на анализ VT. Повторите через 1-2 мин.")
                    elif vt_result.get('malicious', 0) > 1 or vt_result.get('suspicious', 0) > 1:
                        report.append(
                            f"    - `{original_url}`: 🔴 Опасно"
                        )
                    elif vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0:
                         report.append(
                            f"    - `{original_url}`: 🟡 Подозрительно"
                        )
                    else:
                        report.append(
                            f"    - `{original_url}`: ✅ Безопасно"
                        )
                except requests.exceptions.RequestException as e:
                    report.append(f"    - `{original_url}`: ⚠️ Не удалось проверить (Ошибка сети)")
                except Exception as e:
                    report.append(f"    - `{original_url}`: ⚠️ Ошибка при проверке ({type(e).__name__})")
        else:
             report.append("ℹ️ Ссылки в сообщении не найдены.")

        if nlp:
            report.append("\n📝 Анализ текста:")
            text_result = analyze_text(text)
            if text_result.get('error'):
                 report.append(f"    - Ошибка анализа текста: {text_result['error']}")
            elif text_result.get('label') == 'phishing' and text_result.get('score', 0) > 0.5:
                report.append(
                    f"    - 🟡 Подозрительный текст (уверенность: {text_result['score']:.0%})"
                )
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
            bot.send_photo(
                chat_id=message.chat.id,
                photo=photo_file,
                caption=help_text,
                reply_markup=create_main_keyboard()
            )
    except FileNotFoundError:
        print(f"Ошибка: Файл картинки не найден по пути {image_path}")
        bot.send_message(
            message.chat.id,
            help_text + "\n\n(Не удалось загрузить приветственное изображение)",
            reply_markup=create_main_keyboard()
        )
    except Exception as e:
        print(f"Произошла ошибка при отправке фото: {e}")
        bot.send_message(
            message.chat.id,
            "Произошла ошибка при отображении приветствия.",
            reply_markup=create_main_keyboard()
        )

@bot.message_handler(commands=['check'])
def check_handler(message):
    """Обработчик команды /check"""
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
    except IndexError:
        bot.reply_to(message, "Пожалуйста, укажите текст для проверки после команды /check")

@bot.message_handler(content_types=['text'])
def handle_message(message):
    """Основной обработчик текстовых сообщений и кнопок"""
    text = message.text

    if text == "🔍 Проверить сообщение/ссылку":
        bot.reply_to(message, "Хорошо, отправьте мне сообщение, которое нужно проверить.")
    elif text == "🎓 Пройти тест":
        # Вызываем команду safety_test, которая была зарегистрирована через init_safety_test_handlers
        bot.send_message(message.chat.id, "Начинаем тест безопасности!", reply_markup=types.ReplyKeyboardRemove())
        bot.send_message(message.chat.id, "Пожалуйста, используйте команду /safety_test для начала теста")
    elif not text.startswith('/'):
        perform_analysis(message)

if __name__ == "__main__":
    print("Бот запущен...")
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        print(f"Ошибка polling: {e}")
