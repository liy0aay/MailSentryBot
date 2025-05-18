"""
Модуль для анализа фишинга через VirusTotal и NLP.

Классы:
    - VirusTotalClient: Проверка URL через VirusTotal API
    - BaseAnalyzer: Базовый интерфейс для анализаторов сообщений
    - PhishingAnalyzer: Анализ текста и ссылок на фишинг

Требования:
    - Python 3.8+
    - Библиотеки: requests, transformers
"""
import re
import base64
import requests
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification,  AutoModelForSeq2SeqLM
from transformers import MarianMTModel, MarianTokenizer




def translate_ru_to_en(text):

    model_name = 'Helsinki-NLP/opus-mt-ru-en'
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = MarianMTModel.from_pretrained(model_name)


    # разбиваем текст на предложенияим
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())

    # переводим каждое предложение по отдельности и склеиваем обратно
    translations = []
    for sentence in sentences:
        if sentence:
            batch = tokenizer([sentence], return_tensors="pt", truncation=True, padding=True)
            gen = model.generate(**batch)
            translated = tokenizer.batch_decode(gen, skip_special_tokens=True)
            translations.append(translated[0])

    return " ".join(translations)

class VirusTotalClient:
    """Клиент для работы с VirusTotal API.
    
    Предоставляет методы для проверки URL через VirusTotal.
    """     
    def __init__(self, api_key: str):
        """Инициализирует клиент VirusTotal.

        Args:
            api_key (str): API-ключ для доступа к VirusTotal API
        """           
        self.api_key = api_key
        self.headers = {'x-apikey': self.api_key}

    def _handle_api_error(self, response, url: str) -> dict:
        """Обрабатывает ошибки API VirusTotal (внутренний метод).

        Args:
            response: Объект ответа requests
            url (str): Исходный URL, который проверялся

        Returns:
            dict: Сообщение об ошибке или статусе проверки
        """          
        if response.status_code == 404:
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            resp = requests.post(scan_url, headers=self.headers, data={'url': url})
            if resp.status_code == 200:
                return {
                    'status': 'queued',
                    'message': 'URL отправлен на анализ. Повторите позже.'
                }
            return {'error': f"Ошибка отправки: {resp.status_code}"}
        if response.status_code == 429:
            return {'error': 'Превышен лимит запросов'}
        return {'error': f'Ошибка API: {response.status_code}'}

    def check_url(self, url: str) -> dict:
        """Проверяет URL через VirusTotal API.

        Args:
            url (str): URL для проверки

        Returns:
            dict: Результат проверки с ключами:
                - malicious (int): Число детектов как вредоносный
                - suspicious (int): Число подозрительных детектов  
                - harmless (int): Число безопасных детектов
                - error (str): Сообщение об ошибке (при наличии)
        """
        try:
            encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            api_url = f'https://www.virustotal.com/api/v3/urls/{encoded}'
            resp = requests.get(api_url, headers=self.headers, timeout=10)

            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get('data', {})
                    .get('attributes', {})
                    .get('last_analysis_stats', {})
                )
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                }

            return self._handle_api_error(resp, url)

        except requests.exceptions.RequestException as e:
            return {'error': f"Ошибка сети: {e}"}
        except Exception as e:
            return {'error': f"Неизвестная ошибка: {e}"}
        
    def expand_url(self, url: str) -> str:
        """Расширяет короткие или редиректящие URL."""
        full_url = url if url.startswith(('http://', 'https://', 'ftp://')) \
            else f'http://{url}'
        try:
            response = requests.get(full_url, allow_redirects=True, timeout=7,
                                    headers={'User-Agent': 'Mozilla/5.0'})
            return response.url
        except Exception:
            return full_url  # если не удалось, вернём как есть



class BaseAnalyzer:
    """Базовый класс для анализаторов сообщений.
    
    Определяет интерфейс для анализа текста.
    """    
    def analyze_message(self, text: str) -> list:
        """Анализирует текст сообщения.

        Args:
            text (str): Текст для анализа

        Raises:
            NotImplementedError: Если метод не реализован в подклассе

        Returns:
            list: Результаты анализа
        """         
        raise NotImplementedError(
            "Метод должен быть реализован в подклассе"
        )


class PhishingAnalyzer(BaseAnalyzer):
    """Комплексный анализатор фишинговых сообщений.
    
    Совмещает анализ текста через NLP и проверку URL через VirusTotal.
    """  
    def __init__(self, vt_client: VirusTotalClient, nlp_pipeline=None, tokenizer=None):
        """Инициализирует анализатор фишинговых сообщений.

        Args:
            vt_client (VirusTotalClient): Клиент для проверки URL
            nlp_pipeline: NLP-модель для анализа текста (по умолчанию None)
            tokenizer: Токенизатор для NLP-модели (по умолчанию None)
        """       
        self.vt_client = vt_client
        self.nlp = nlp_pipeline
        self.tokenizer = tokenizer

        """Анализирует текст на признаки фишинга.

        Args:
            text (str): Текст для анализа

        Returns:
            dict: Результат анализа с меткой и уверенностью
        """               

    def analyze_text(self, text: str) -> dict:
        """Анализирует текст на признаки фишинга.

        Args:
            text (str): Текст для анализа

        Returns:
            dict: Результат анализа с меткой и уверенностью
        """               
        if not self.nlp:
            return {'error': 'Модель не загружена'}
        
        # Если в тексте есть кириллица, перевести его на английский
        if re.search(r'[а-яА-Я]', text):
            try:
                print("подаем:", text)
                text = translate_ru_to_en(text)
                print(text) #test
            except Exception as e:
                return {'error': f"Ошибка перевода: {e}"}


        try:
            
            result = self.nlp(text)[0]
            print(result)
            return {
                'label': 'phishing' if result['label'] == 'phishing' else 'safe',
                'score': result['score'],
            }
        except Exception as e:
            return {'error': str(e)}

    def extract_urls(self, text: str) -> list:
        """Извлекает URL из текста.

        Args:
            text (str): Текст для поиска URL

        Returns:
            list: Список найденных URL
        """   
        return re.findall(
            r'(?:(?:https?|ftp):\/\/)?'
            r'(?:www\.)?'
            r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
            r'(?:\/[^\s]*)?',
            text
        )
    
    def format_url_result(self, url: str, result: dict) -> str:
        """
        Форматирует результат проверки URL в виде строки для отчета.

        Args:
            url (str): Исходный URL, предоставленный пользователем.
            result (dict): Результат проверки URL от VirusTotal (может содержать поля 'error', 'status', 'malicious', 'suspicious').

        Returns:
            str: Cтрока с оценкой URL (Опасно, Подозрительно, Безопасно).
    """
        if result.get('error'):
            return f"    - `{url}`: ⚠️ {result['error']}"
        if result.get('status') == 'queued':
            return f"    - `{url}`: ⏳ Отправлен на анализ"
        if result.get('malicious', 0) > 1 or result.get('suspicious', 0) > 1:
            return f"    - `{url}`: 🔴 Опасно"
        if result.get('malicious', 0) > 0 or result.get('suspicious', 0) > 0:
            return f"    - `{url}`: 🟡 Подозрительно"
        return f"    - `{url}`: ✅ Безопасно"

    def _check_url_risk(self, url: str) -> str:
        """
        Проверяет степень риска для URL, включая его расширение и анализ через VirusTotal.

        Args:
            url (str): URL, извлечённый из текста сообщения.

        Returns:
            str: Отформатированная строка с результатом анализа (например: "🔴 Опасно", "✅ Безопасно" и т. д.).
    """
        try:
            expanded_url = self.vt_client.expand_url(url)
            result = self.vt_client.check_url(expanded_url)
            return self.format_url_result(url, result)
        except Exception as e:
            return f"    - `{url}`: ⚠️ Ошибка ({type(e).__name__})"


    def analyze_message(self, text: str) -> list:
        """Анализирует сообщение на фишинг.

        Args:
            text (str): Текст сообщения для анализа

        Returns:
            list: Отчет с результатами анализа URL и текста
        """          
        report = []

        urls = self.extract_urls(text)
        if urls:
            report.append("🔎 Анализ ссылок:")
            for url in urls:
                report.append(self._check_url_risk(url))
        else:
            report.append("ℹ️ Ссылки не найдены.")

        report.append("\n📝 Анализ текста:")
        result = self.analyze_text(text)

        if result.get('error'):
            report.append(f"    - Ошибка анализа текста: {result['error']}")
        elif result['label'] == 'phishing' and result['score'] > 0.5:
            confidence = f"{result['score']:.0%}"
            report.append(f"    - 🟡 Подозрительный текст (уверенность: {confidence})")
        else:
            report.append("    - ✅ Текст не выглядит подозрительным.")

        return report