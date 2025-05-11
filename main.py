import os
import re
import base64
import requests

from typing import Dict, List

from dotenv import load_dotenv
import telebot
from telebot import types

from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

from safe_test import init_safety_test_handlers
from analyzers import VirusTotalClient, PhishingAnalyzer, BaseAnalyzer


# загрузка переменных окружения
load_dotenv()
API_TOKEN = os.getenv("API_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not API_TOKEN or not VIRUSTOTAL_API_KEY:
    raise ValueError("Отсутствуют необходимые переменные окружения")


# загрузка NLP-модели
def load_nlp_model():
    try:
        model_name = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        nlp = pipeline("text-classification", model=model, tokenizer=tokenizer)
        return nlp, tokenizer
    except Exception as e:
        print(f"Ошибка загрузки модели: {e}")
        return None, None


nlp, tokenizer = load_nlp_model()
vt_client = VirusTotalClient(VIRUSTOTAL_API_KEY)
analyzer = PhishingAnalyzer(vt_client, nlp, tokenizer)
bot = telebot.TeleBot(API_TOKEN)


# анализ
def perform_analysis(message: types.Message, analyzer: BaseAnalyzer):
    results = analyzer.analyze_message(message.text)
    bot.send_message(message.chat.id, "\n".join(results))


# главное меню
def create_main_keyboard():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(
        types.KeyboardButton("🔍 Проверить сообщение/ссылку"),
        types.KeyboardButton("🎓 Пройти тест")
    )
    return markup


# приветствие
def get_help_text():
    return (
        "👋 Привет! Я антифишинговый бот.\n\n"
        "🛡️ Мои возможности:\n"
        "- Проверка сообщений: Анализирую текст и ссылки на фишинг и вредоносность с помощью NLP и VirusTotal.\n"
        "- Тест безопасности: Проверь свои знания о цифровых угрозах.\n\n"
        "👇 Используй кнопки ниже"
    )


# инициализация теста
user_progress = {}
init_safety_test_handlers(bot, user_progress, create_main_keyboard)


# обработчики
@bot.message_handler(commands=["start", "help"])
def send_welcome(message):
    try:
        with open("CyberSentry.png", "rb") as photo_file:
            bot.send_photo(
                chat_id=message.chat.id,
                photo=photo_file,
                caption=get_help_text(),
                reply_markup=create_main_keyboard()
            )
    except FileNotFoundError:
        bot.send_message(
            message.chat.id,
            get_help_text() + "\n\n(Не удалось загрузить изображение)",
            reply_markup=create_main_keyboard()
        )
    except Exception as e:
        print(f"Ошибка при отправке приветствия: {e}")
        bot.send_message(
            message.chat.id,
            "Произошла ошибка при отображении приветствия.",
            reply_markup=create_main_keyboard()
        )


@bot.message_handler(commands=["check"])
def check_handler(message):
    try:
        text_to_check = message.text.split(None, 1)[1]
        result = analyzer.analyze_message(text_to_check)
        bot.reply_to(message, "\n".join(result), parse_mode="Markdown")
    except IndexError:
        bot.reply_to(
            message,
            "Пожалуйста, укажите текст для проверки после команды /check"
        )


@bot.message_handler(content_types=["text"])
def handle_message(message):
    text = message.text.strip()

    if text == "🔍 Проверить сообщение/ссылку":
        bot.reply_to(message, "Хорошо, отправьте мне сообщение, которое нужно проверить.")
    elif text == "🎓 Пройти тест":
        bot.send_message(
            message.chat.id,
            "Начинаем тест!",
            reply_markup=types.ReplyKeyboardRemove()
        )
        bot.send_message(
            message.chat.id,
            "Пожалуйста, используйте команду /safety_test для начала теста"
        )
    elif not text.startswith("/"):
        perform_analysis(message, analyzer)


if __name__ == "__main__":
    print("Бот запущен...")
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        print(f"Ошибка polling: {e}")