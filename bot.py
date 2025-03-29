import telebot
import requests
import re
import base64
#from flask import Flask, request
from telebot import types
from transformers import pipeline
from typing import List, Dict
from dotenv import load_dotenv
import os

load_dotenv()  
API_TOKEN = os.getenv("API_TOKEN")  
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not API_TOKEN:
    raise ValueError("Telegram token not found! Check .env file")

bot = telebot.TeleBot(API_TOKEN)
# app = Flask(__name__)

# Инициализация NLP-модели
try:
    nlp = pipeline(
        "text-classification",
        model="valurank/phishing-bert-tiny",  # Рабочая альтернатива
        tokenizer="valurank/phishing-bert-tiny"
    )
except Exception as e:
    print(f"Error loading NLP model: {e}")
    nlp = None

# Тест безопасности
SAFETY_QUESTIONS = [
    {
        "question": "Что делать при получении письма с просьбой обновить пароль?",
        "options": [
            "Немедленно перейти по ссылке",
            "Проверить отправителя и сайт вручную",
            "Переслать другу для проверки"
        ],
        "correct": 1,
        "explanation": "✅ Правильно! Всегда проверяйте адрес отправителя и вводите данные только на официальных сайтах."
    },
    {
        "question": "Какой пароль наиболее безопасен?",
        "options": [
            "123456",
            "qwerty",
            "H7$kL9!vRn2*"
        ],
        "correct": 2,
        "explanation": "✅ Верно! Надежный пароль должен содержать минимум 12 символов с цифрами и спецсимволами."
    }
]

user_progress = {}

# Вспомогательные функции
def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_url_virustotal(url: str) -> Dict:
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    encoded_url = encode_url(url)
    
    try:
        report_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats['malicious'],
                'suspicious': stats['suspicious'],
                'harmless': stats['harmless']
            }
        elif response.status_code == 404:
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            response = requests.post(scan_url, headers=headers, data={'url': url})
            if response.status_code == 200:
                return {'status': 'queued', 'message': 'URL отправлен на анализ'}
        
        return {'error': f"API error: {response.status_code}"}
    
    except Exception as e:
        return {'error': str(e)}

def analyze_text(text: str) -> Dict:
    try:
        if not nlp:
            return {'error': 'Модель не загружена. Проверка текста недоступна'}
            
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

# Установка вебхука
# @app.route('/')
# def set_webhook():
#     bot.remove_webhook()
#     bot.set_webhook(url='https://szcm4wo.pythonanywhere.com')
#     return "Webhook установлен!"

# Обработчик входящих сообщений
# @app.route('/webhook', methods=['POST'])
# def webhook():
#     update = telebot.types.Update.de_json(request.stream.read().decode('utf-8'))
#     bot.process_new_updates([update])
#     return 'OK', 200

# Обработчики сообщений
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    help_text = """
🔍 Я антифишинговый бот! Проверю:
- Ссылки через VirusTotal
- Текст на подозрительные фразы
- Даю рекомендации по безопасности

Команды:
/safety_test - Тест знаний безопасности
/check [текст] - Проверить сообщение
"""
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['safety_test'])
def start_safety_test(message):
    user_id = message.from_user.id
    user_progress[user_id] = {"current_question": 0, "correct": 0}
    ask_question(message.chat.id, user_id)

def ask_question(chat_id, user_id):
    markup = types.InlineKeyboardMarkup()
    question_data = SAFETY_QUESTIONS[user_progress[user_id]["current_question"]]
    
    for idx, option in enumerate(question_data["options"]):
        markup.add(types.InlineKeyboardButton(
            text=option,
            callback_data=f"answer_{user_progress[user_id]['current_question']}_{idx}"
        ))
    
    bot.send_message(chat_id, 
        f"Вопрос {user_progress[user_id]['current_question']+1}/{len(SAFETY_QUESTIONS)}\n\n" +
        question_data["question"], 
        reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('answer_'))
def handle_answer(call):
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
        
        if score == 1:
            feedback = "🎉 Отличный результат! Вы отлично разбираетесь в безопасности!"
        elif score >= 0.7:
            feedback = "👍 Хорошо, но есть куда расти:"
        else:
            feedback = "⚠️ Нужно подтянуть знания:"
        
        recommendations = [
            "🔹 Всегда используйте двухфакторную аутентификацию",
            "🔹 Обновляйте ПО и антивирусы",
            "🔹 Не используйте одинаковые пароли",
            "🔹 Проверяйте HTTPS в адресе сайта",
            "🔹 Делайте резервные копии данных"
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
    try:
        text = message.text
        report = []
        
        urls = re.findall(r'https?://\S+', text)
        for url in urls:
            vt_result = check_url_virustotal(url)
            if 'malicious' in vt_result and vt_result['malicious'] > 5:
                report.append(
                    f"🔴 Опасная ссылка: {url}\n"
                    f"• Вредоносных детектов: {vt_result['malicious']}\n"
                    f"• Подозрительных: {vt_result['suspicious']}"
                )
        
        if not urls:
            text_result = analyze_text(text)
            if 'error' not in text_result:
                if text_result['label'] == 'phishing' and text_result['score'] > 0.85:
                    report.append(
                        f"🟡 Подозрительный текст\n"
                        f"• Уверенность: {text_result['score']:.0%}\n"
                        f"• Ключевые слова: {', '.join(text_result['keywords'])}"
                    )
        
        if report:
            bot.reply_to(message, "\n\n".join(report))
        else:
            bot.reply_to(message, "✅ Сообщение безопасно")
    
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка обработки: {str(e)}")

if __name__ == "__main__":
    print("Бот запущен...")
    # app.run(host='0.0.0.0', port=5000)
    bot.polling(none_stop=True)