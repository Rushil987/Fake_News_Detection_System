import re
from config.settings import BLACKLISTED_NEWS_DOMAINS

class AuthenticityFilter:
    def __init__(self, trusted_sources):
        self.trusted_sources = trusted_sources

    def check_source_authenticity(self, article_data):
        domain = article_data.get('domain', '').lower()
        if domain in BLACKLISTED_NEWS_DOMAINS:
            return 0.0
        if any(trusted in domain for trusted in self.trusted_sources):
            return 0.8
        if domain.count('.') > 2:
            return 0.2
        return 0.5

    def check_content_authenticity(self, article_data):
        content = article_data.get('content', '')
        title = article_data.get('title', '')
        score = 0.5
        if title:
            caps_ratio = sum(1 for c in title if c.isupper()) / len(title)
            if caps_ratio > 0.5:
                score -= 0.2
        word_count = len(content.split())
        if word_count < 50:
            score -= 0.3
        return max(0, min(1, score))

    def apply_authenticity_filter(self, article_data):
        source_score = self.check_source_authenticity(article_data)
        content_score = self.check_content_authenticity(article_data)
        overall_score = (source_score * 0.6) + (content_score * 0.4)
        article_data['source_trust_score'] = source_score
        article_data['content_trust_score'] = content_score
        article_data['overall_authenticity_score'] = overall_score
        if overall_score < 0.3:
            return 'BLOCK', 'Low authenticity score'
        elif len(article_data.get('content', '').split()) < 20:
            return 'BLOCK', 'Insufficient content'
        return 'PASS', 'Passed authenticity check'
        