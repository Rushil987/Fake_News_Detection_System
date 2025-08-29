import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

# Paths to domain quality database CSV files
DOMAIN_QUALITY_DB_PATH = os.path.join(BASE_DIR, "data", "domain_pc1.csv")
DOMAIN_RATINGS_PATH = os.path.join(BASE_DIR, "data", "domain_ratings.csv")

# Preprocessing settings
MIN_ARTICLE_LENGTH = 50
MAX_ARTICLE_LENGTH = 10000

# WHOISXML API key (optional, for urlworkxml.py)

WHOISXML_API_KEY = ""
