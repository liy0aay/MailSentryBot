import telebot
import requests
import re
import base64
import os
from telebot import types
from transformers import pipeline
from dotenv import load_dotenv

# Загружаем токены из .env
load_dotenv()  
API_TOKEN = os.getenv("API_TOKEN")  
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not API_TOKEN:
    raise ValueError("❌ Telegram API_TOKEN не найден! Проверь .env файл")

bot = telebot.TeleBot(API_TOKEN)

# Загружаем NLP-модель
try:
    nlp = pipeline(
        "text-classification",
        model="valurank/phishing-bert-tiny",
        tokenizer="valurank/phishing-bert-tiny"
    )
except Exception as e:
    print(f"⚠️ Ошибка загрузки NLP-модели: {e}")
    nlp = None

# Функции для работы с URL и VirusTotal
def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def check_url_virustotal(url: str):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    encoded_url = encode_url(url)
    
    try:
        report_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
        response = requests.get(report_url, headers=headers)
        
        print(f"📡 VirusTotal API Response: {response.status_code}")

        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0)
            }
        elif response.status_code == 404:
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            response = requests.post(scan_url, headers=headers, data={'url': url})
            if response.status_code == 200:
                return {'status': 'queued', 'message': '🔄 URL отправлен на анализ'}
        
        return {'error': f"⚠️ API error: {response.status_code}"}
    
    except Exception as e:
        return {'error': str(e)}

def analyze_text(text: str):
    try:
        if not nlp:
            return {'error': '❌ NLP-модель не загружена'}
            
        result = nlp(text[:512])[0]
        phishing_keywords = {
            'password', 'account', 'verify', 'security',
            'пароль', 'карта', 'срочно', 'перевод', 'банк', 'логин'
        }
        found_keywords = set(word for word in re.findall(r'\w+', text.lower()) if word in phishing_keywords)
        
        return {
            'label': 'phishing' if result['label'] == 'phishing' else 'safe',
            'score': result['score'],
            'keywords': list(found_keywords)
        }
    
    except Exception as e:
        return {'error': str(e)}

# Команда /start и /help
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    help_text = """
👋 Привет! Я антифишинговый бот.

🔍 Я умею:
- Проверять ссылки через VirusTotal
- Анализировать текст на мошенничество
- Давать советы по кибербезопасности

🛡 Команды:
/check [текст] — Проверить сообщение
/safety_test — Пройти тест по безопасности
"""
    bot.reply_to(message, help_text)

# Команда /check
@bot.message_handler(commands=['check'])
def check_message(message):
    text = message.text.replace("/check", "").strip()
    if not text:
        bot.reply_to(message, "❌ Пожалуйста, укажите текст или ссылку для проверки!")
        return

    report = []
    urls = re.findall(r'https?://\S+', text)
    
    # Проверка URL
    for url in urls:
        vt_result = check_url_virustotal(url)
        if 'malicious' in vt_result and vt_result['malicious'] > 5:
            report.append(f"🔴 Опасная ссылка: {url}\n"
                          f"• Вредоносных детектов: {vt_result['malicious']}\n"
                          f"• Подозрительных: {vt_result['suspicious']}")
    
    # Проверка текста
    text_result = analyze_text(text)
    if 'error' not in text_result and text_result['label'] == 'phishing' and text_result['score'] > 0.7:
        report.append(f"⚠️ Подозрительный текст\n"
                      f"• Уверенность: {text_result['score']:.0%}\n"
                      f"• Ключевые слова: {', '.join(text_result['keywords'])}")

    # Ответ пользователю
    if report:
        bot.reply_to(message, "\n\n".join(report))
    else:
        bot.reply_to(message, "✅ Сообщение безопасно")

# Обработчик всех остальных сообщений
@bot.message_handler(func=lambda message: True)
def default_message_handler(message):
    bot.reply_to(message, "🤖 Используйте команду /check для проверки сообщений или /help для списка команд.")

if __name__ == "__main__":
    print("🚀 Бот запущен!")
    bot.polling(none_stop=True)