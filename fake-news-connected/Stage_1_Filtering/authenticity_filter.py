from domain_quality.domain_quality import DomainQualityDB

class AuthenticityFilter:
    def __init__(self):
        self.db = DomainQualityDB()

    def check_source_authenticity(self, article_data):
        domain = article_data.get('domain', '').lower()
        domain_info = self.db.get_domain_info(domain)

        score = domain_info['score']
        reason = domain_info['reason']
        status = domain_info['status']
        reference = domain_info['reference']

        # Attach trust info to article data for traceability
        article_data['domain_score'] = score
        article_data['domain_status'] = status
        article_data['domain_reason'] = reason
        article_data['domain_reference'] = reference

        return score, reason

    def check_content_authenticity(self, article_data):
        content = article_data.get('content', '')
        title = article_data.get('title', '')
        
        score = 0.5  # Base neutral content score
        
        if title:
            caps_ratio = sum(1 for c in title if c.isupper()) / len(title)
            if caps_ratio > 0.5:
                score = max(0, score - 0.2)
        
        word_count = len(content.split())
        if word_count < 50:
            score = max(0, score - 0.3)
        
        return score

    def apply_authenticity_filter(self, article_data):
        source_score, source_reason = self.check_source_authenticity(article_data)
        content_score = self.check_content_authenticity(article_data)
        overall_score = (source_score * 0.6) + (content_score * 0.4)

        article_data['source_trust_score'] = source_score
        article_data['source_trust_reason'] = source_reason
        article_data['content_trust_score'] = content_score
        article_data['overall_authenticity_score'] = overall_score

        if overall_score < 0.3:
            return 'BLOCK', 'Low authenticity score. Article likely unreliable.'
        elif len(article_data.get('content', '').split()) < 20:
            return 'BLOCK', 'Content too short for reliable analysis.'
        return 'PASS', 'Passed authenticity check.'
        