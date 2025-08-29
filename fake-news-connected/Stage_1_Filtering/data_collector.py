import requests
from bs4 import BeautifulSoup
from datetime import datetime
import logging
from urllib.parse import urlparse

class NewsDataCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    def collect_from_url(self, url):
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.find('title').text if soup.find('title') else ""
            content = ""
            for tag in ['article', 'div.content', 'div.story']:
                element = soup.select_one(tag)
                if element:
                    content = element.get_text()
                    break
            return {
                'url': url,
                'domain': self.extract_domain(url),
                'title': title,
                'content': content,
                'collection_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"URL collection error for {url}: {str(e)}")
            return None

    def collect_from_text_input(self, text, title="", source="user_input"):
        return {
            'content': text,
            'title': title,
            'domain': source,
            'collection_timestamp': datetime.now().isoformat(),
            'source_type': 'manual_input'
        }

    def extract_domain(self, url):
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain