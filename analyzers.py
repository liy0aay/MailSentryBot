import re
import base64
import requests
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {'x-apikey': self.api_key}

    def _handle_api_error(self, response, url: str) -> dict:
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
    def analyze_message(self, text: str) -> list:
        raise NotImplementedError(
            "Метод должен быть реализован в подклассе"
        )


class PhishingAnalyzer(BaseAnalyzer):
    def __init__(self, vt_client: VirusTotalClient, nlp_pipeline=None, tokenizer=None):
        self.vt_client = vt_client
        self.nlp = nlp_pipeline
        self.tokenizer = tokenizer

    def analyze_text(self, text: str) -> dict:
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
        return re.findall(
            r'(?:(?:https?|ftp):\/\/)?'
            r'(?:www\.)?'
            r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
            r'(?:\/[^\s]*)?',
            text
        )

    def _check_url_risk(self, url: str) -> str: # метод строго внутри класса
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