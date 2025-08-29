import os
import pandas as pd

RESEARCH_REFERENCE = (
    "Lin, H.; Lasser, J.; Lewandowsky, S.; Cole, R.; Gully, A.; Rand, D.G.; Pennycook, G. "
    "(2023). High level of correspondence across different news domain quality rating sets. "
    "PNAS Nexus, 2(9), pgad286."
)

class DomainQualityDB:
    def __init__(self, db_path=None):
        if db_path is None:
            # Adjust base_dir if needed based on your project structure
            base_dir = os.path.abspath(os.path.dirname(__file__))
            db_path = os.path.join(base_dir, "..", "data", "domain_pc1.csv")
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Domain quality DB file not found at {db_path}")

        # Load CSV into pandas DataFrame for fast querying
        try:
            self.df = pd.read_csv(db_path)
            print("Dataframe successfully loaded")
            self.df['domain'] = self.df['domain'].str.lower()
            print(f"Loaded dataframe with {len(self.df)} rows")
        except Exception as e:
            print("Error loading CSV:", e)
            raise 

    def get_domain_info(self, domain):
        domain = domain.lower().strip()
        if domain == '':
            return {
                "domain": "",
                "score": 0.5,
                "status": "unknown",
                "reason": "No domain provided - default unknown status",
                "reference": RESEARCH_REFERENCE,
            }
        result = self.df[self.df['domain'] == domain]
        if result.empty:
            return {
                "domain": domain,
                "score": 0.5,
                "status": "unknown",
                "reason": "Domain not found in expert-rated dataset.",
                "reference": RESEARCH_REFERENCE,
            }
        score = float(result['pc1'])
        if score >= 0.8:
            status = "trusted"
            reason = "Aggregated expert ratings indicate this is a highly trusted news source."
        elif score <= 0.2:
            status = "blacklisted"
            reason = "Aggregated expert ratings indicate this is a low-quality or potentially misleading source."
        else:
            status = "unknown"
            reason = "Domain is rated as intermediate quality."
        return {
            "domain": domain,
            "score": score,
            "status": status,
            "reason": reason,
            "reference": RESEARCH_REFERENCE,
        }