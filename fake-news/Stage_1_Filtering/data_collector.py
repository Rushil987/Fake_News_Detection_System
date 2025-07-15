import requests
from bs4 import BeautifulSoup
from datetime import datetime
import logging
from urllib.parse import urlparse
from config.settings import TRUSTED_SOURCES, SOCIAL_MEDIA_DOMAINS

class NewsDataCollector:
    def __init__(self):
        self.trusted_sources = TRUSTED_SOURCES
        self.social_media_domains = SOCIAL_MEDIA_DOMAINS
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    def collect_from_url(self, url):
        try:
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.find('title').text if soup.find('title') else ""
            content = ""
            for tag in ['article', 'div.content', 'div.story']:
                if element := soup.select_one(tag):
                    content = element.get_text()
                    break
            return {
                'url': url,
                'domain': self.extract_domain(url),
                'title': title,
                'content': content,
                'source_type': self._classify_source_type(url),
                'collection_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"URL collection error: {str(e)}")
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
        return urlparse(url).netloc.lower()

    def _classify_source_type(self, url):
        domain = self.extract_domain(url)
        if any(trusted in domain for trusted in self.trusted_sources):
            return 'trusted_news'
        elif any(social in domain for social in self.social_media_domains):
            return 'social_media'
        return 'unknown'