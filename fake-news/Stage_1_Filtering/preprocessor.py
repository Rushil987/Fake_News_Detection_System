import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from config.settings import MIN_ARTICLE_LENGTH, MAX_ARTICLE_LENGTH

nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

class NewsPreprocessor:
    def __init__(self):
        self.stemmer = PorterStemmer()
        self.stop_words = set(stopwords.words('english'))
    
    def clean_text(self, text):
        if not text: return ""
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'http\S+', '', text)
        text = re.sub(r'[^\w\s.,!?-]', '', text)
        return re.sub(r'\s+', ' ', text).strip()
    
    def tokenize_text(self, text):
        text = self.clean_text(text).lower()
        tokens = word_tokenize(text)
        return [token for token in tokens if token not in self.stop_words and len(token) > 2]
    
    def stem_tokens(self, tokens):
        return [self.stemmer.stem(token) for token in tokens]
    
    def apply_processing_rules(self, article_data):
        content = article_data.get('content', '')
        word_count = len(content.split())
        if word_count < MIN_ARTICLE_LENGTH:
            return 'BLOCK', 'Content too short'
        if word_count > MAX_ARTICLE_LENGTH:
            return 'BLOCK', 'Content too long'
        if not article_data.get('title', '').strip():
            return 'BLOCK', 'Missing title'
        return 'PASS', 'Passed preprocessing'
    
    def preprocess_article(self, article_data):
        rule_decision, rule_reason = self.apply_processing_rules(article_data)
        processed = article_data.copy()
        processed.update({
            'rule_decision': rule_decision,
            'rule_reason': rule_reason
        })
        if rule_decision == 'PASS':
            content = processed.get('content', '')
            processed['content_clean'] = self.clean_text(content)
            tokens = self.tokenize_text(content)
            processed['content_tokens'] = tokens
            processed['content_stemmed'] = self.stem_tokens(tokens)
            processed['word_count'] = len(tokens)
        return processed