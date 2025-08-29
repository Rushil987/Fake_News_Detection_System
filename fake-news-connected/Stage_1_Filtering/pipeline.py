import logging
from Stage_1_Filtering.data_collector import NewsDataCollector
from Stage_1_Filtering.authenticity_filter import AuthenticityFilter
from Stage_1_Filtering.preprocessor import NewsPreprocessor
from config.settings import WHOISXML_API_KEY
from urlworkxml import detect_phishing, get_domain, check_redirection

class Stage1Pipeline:
    def __init__(self):
        self.collector = NewsDataCollector()
        self.auth_filter = AuthenticityFilter()
        self.preprocessor = NewsPreprocessor()
        self.logger = logging.getLogger(__name__)
    
    def process_url(self, url):
        self.logger.info(f"Processing URL: {url}")
        article_data = self.collector.collect_from_url(url)
        if not article_data: 
            return None

        domain = article_data.get('domain')
        if domain and WHOISXML_API_KEY:
            phishing_result = self._run_domain_check(url, domain)
            article_data['domain_check'] = phishing_result

        decision, reason = self.auth_filter.apply_authenticity_filter(article_data)
        article_data.update({
            'filter_decision': decision,
            'filter_reason': reason
        })
        if decision == 'BLOCK':
            return article_data

        processed = self.preprocessor.preprocess_article(article_data)
        processed['ready_for_stage2'] = processed['rule_decision'] == 'PASS'
        return processed
    
    def process_text(self, text, title=""):
        article_data = self.collector.collect_from_text_input(text, title)
        
        decision, reason = self.auth_filter.apply_authenticity_filter(article_data)
        article_data.update({
            'filter_decision': decision,
            'filter_reason': reason
        })
        if decision == 'BLOCK':
            return article_data
        
        processed = self.preprocessor.preprocess_article(article_data)
        processed['ready_for_stage2'] = processed['rule_decision'] == 'PASS'
        return processed

    def _run_domain_check(self, url, domain):
        final_url = check_redirection(url)
        if final_url and get_domain(final_url) != domain:
            return {
                'risk': 'High',
                'warning': 'Suspicious redirection detected',
                'details': f'Redirects to {final_url}'
            }
        return {
            'risk': 'Low',
            'warning': None,
            'details': 'No suspicious redirection'
        }