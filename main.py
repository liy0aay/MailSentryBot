"""
Антифишинговый Telegram бот для анализа безопасности сообщений

Основные функции:
- Анализ текста на фишинг с использованием NLP моделей
- Проверка URL через VirusTotal API
- Интерактивный тест знаний по кибербезопасности
- Пользовательский интерфейс с кнопками и обработкой команд

Требуемые переменные окружения:
- API_TOKEN: Токен Telegram бота
- VIRUSTOTAL_API_KEY: Ключ для VirusTotal API

Используемые технологии:
- Python-telegram-bot для работы с Telegram API
- Transformers для NLP анализа
- VirusTotal API для проверки URL

Raises:
    ValueError: При отсутсвии необходимых переменных окружения

"""
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


def load_nlp_model():
    """Загружает и инициализирует NLP модель для детекции спама/фишинга.

    Returns:
        tuple: (nlp_pipeline, tokenizer) - пайплайн обработки текста и токенизатор
        или (None, None) в случае ошибки

    Raises:
        Exception: При ошибках загрузки модели или токенизатора
    """   
    try:
        model_name = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        nlp = pipeline("text-classification", model=model, tokenizer=tokenizer)
        return nlp, tokenizer
    except Exception as e:
        print(f"Ошибка загрузки модели: {e}")
        return None, None

# Инициализация компонентов
nlp, tokenizer = load_nlp_model()
vt_client = VirusTotalClient(VIRUSTOTAL_API_KEY)
analyzer = PhishingAnalyzer(vt_client, nlp, tokenizer)
bot = telebot.TeleBot(API_TOKEN)


def perform_analysis(message: types.Message, analyzer: BaseAnalyzer):
    """Выполняет анализ сообщения на фишинг и отправляет результат пользователю.

    Args:
        message (types.Message): Объект сообщения от пользователя
        analyzer (BaseAnalyzer): Анализатор для проверки сообщений
    """
    results = analyzer.analyze_message(message.text)
    bot.send_message(message.chat.id, "\n".join(results))


def create_main_keyboard():
    """Создает клавиатуру с основными командами.

    Returns:
        types.ReplyKeyboardMarkup: Клавиатура с кнопками для проверки сообщения/ссылки и для прохождения теста
    """  
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(
        types.KeyboardButton("🔍 Проверить сообщение/ссылку"),
        types.KeyboardButton("🎓 Пройти тест")
    )
    return markup


def get_help_text():
    """Генерирует текст справки о возможностях бота.

    Returns:
        str: Форматированное описание функционала бота
    """ 
    return (
        "👋 Привет! Я антифишинговый бот.\n\n"
        "🛡️ Мои возможности:\n"
        "- Проверка сообщений: Анализирую текст и ссылки на фишинг и вредоносность с помощью NLP и VirusTotal.\n"
        "- Тест безопасности: Проверь свои знания о цифровых угрозах.\n\n"
        "👇 Используй кнопки ниже"
    )


# инициализация теста по безопасности
user_progress = {}
init_safety_test_handlers(bot, user_progress, create_main_keyboard)


@bot.message_handler(commands=["start", "help"])
def send_welcome(message):
    """Обрабатывает команды /start и /help, отправляет приветственное сообщение.

    Args:
        message (types.Message): Входящее сообщение от пользователя

    Behavior:
        - Отправляет логотип с описанием функционала
        - В случае ошибки отправляет текстовое описание
    """ 
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
    """Обрабатывает команду /check для ручной проверки текста.

    Args:
        message (types.Message): Сообщение с командой и текстом для проверки

    Behavior:
        - Извлекает текст после команды /check
        - Анализирует текст через анализатор
        - Отправляет результат пользователю
    """
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
    """Обрабатывает текстовые сообщения от пользователя.

    Args:
        message (types.Message): Входящее текстовое сообщение

    Behavior:
        - Для кнопки проверки: запрашивает сообщение для анализа
        - Для кнопки теста: запускает тест безопасности
        - Для обычного текста: выполняет анализ на фишинг
    """
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