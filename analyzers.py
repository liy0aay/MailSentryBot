"""
Модуль для анализа фишинга через VirusTotal и NLP.

Классы:
    - VirusTotalClient: Проверка URL через VirusTotal API
    - PhishingAnalyzer: Анализ текста и ссылок на фишинг

Требования:
    - Python 3.8+
    - Библиотеки: requests, transformers
"""
import re
import base64
import requests
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

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

    def analyze_text(self, text: str) -> dict:
        """Анализирует текст на признаки фишинга.

        Args:
            text (str): Текст для анализа

        Returns:
            dict: Результат анализа с меткой и уверенностью
        """               
        if not self.nlp or not self.tokenizer:
            return {'error': 'Модель не загружена'}

        try:
            inputs = self.tokenizer(
                text, return_tensors="pt", truncation=True, max_length=512
            )
            truncated = self.tokenizer.decode(
                inputs["input_ids"][0], skip_special_tokens=True
            )
            result = self.nlp(truncated)[0]
            return {
                'label': 'phishing' if result['label'] == 'LABEL_1' else 'safe',
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

    def _check_url_risk(self, url: str) -> str: # метод строго внутри класса
        """Проверяет риск URL (внутренний метод).

        Args:
            url (str): URL для проверки

        Returns:
            str: Форматированная строка с результатом проверки
        """ 
        full_url = url if url.startswith(('http://', 'https://', 'ftp://')) \
            else f'http://{url}'
        try:
            response = requests.get(
                full_url, allow_redirects=True, timeout=7,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            expanded = response.url
            result = self.vt_client.check_url(expanded)

            if result.get('error'):
                return f"    - `{url}`: ⚠️ {result['error']}"
            if result.get('status') == 'queued':
                return f"    - `{url}`: ⏳ Отправлен на анализ"
            if result.get('malicious', 0) > 1 or result.get('suspicious', 0) > 1:
                return f"    - `{url}`: 🔴 Опасно"
            if result.get('malicious', 0) > 0 or result.get('suspicious', 0) > 0:
                return f"    - `{url}`: 🟡 Подозрительно"
            return f"    - `{url}`: ✅ Безопасно"
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