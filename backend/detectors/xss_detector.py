import ast
import re
from backend.core.vulnerability_scorer import VulnerabilityScorer

class XSSDetector:
    """
    Détecteur XSS : repère l’injection de scripts ou l’insertion de données non échappées
    dans du HTML (templates Jinja2, f-strings, concatenations).
    """
    def __init__(self):
        self.scorer = VulnerabilityScorer()
        # Patterns XSS courants (<script>, innerHTML, dangerouslySetInnerHTML, etc.)
        self.xss_patterns = [
            r"<\s*script",                # balise script
            r"\.innerHTML",               # affectation innerHTML
            r"dangerouslySetInnerHTML",   # React
            r"document\.write",           # écriture directe
        ]

    def analyze_xss(self, source_code: str):
        tree = ast.parse(source_code)
        vulnerabilities = []
        for node in ast.walk(tree):
            # 1. Recherche de patterns dans les constantes ou f-strings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pat in self.xss_patterns:
                    if re.search(pat, node.value, re.IGNORECASE):
                        evidence = {
                            "direct_pattern_match": True,
                            "user_input_flow": False,
                            "context_complete": False
                        }
                        score = self.scorer.calculate_confidence_score(evidence)
                        status, _ = self.scorer.interpret_score(score)
                        vulnerabilities.append({
                            "type": "XSS",
                            "line": node.lineno,
                            "pattern": pat,
                            "description": f"Pattern XSS détecté : «{pat}» dans {node.value[:30]}…",
                            "confidence_score": score,
                            "confidence_status": status,
                            "severity": "MEDIUM"
                        })
            # 2. Analyse des appels à `render` / `format` potentiellement dangereux
            if isinstance(node, ast.Call) and hasattr(node.func, "attr"):
                func_name = node.func.attr.lower()
                if func_name in ("render", "format"):
                    # cas simplifié : on considère un risque si l’argument est une f-string ou contient des {}
                    for arg in node.args:
                        src = ast.get_source_segment(source_code, arg) or ""
                        if "{" in src and "}" in src:
                            evidence = {"direct_pattern_match": True}
                            score = self.scorer.calculate_confidence_score(evidence)
                            status, _ = self.scorer.interpret_score(score)
                            vulnerabilities.append({
                                "type": "XSS",
                                "line": node.lineno,
                                "description": "Usage de render/format sans échappement",
                                "confidence_score": score,
                                "confidence_status": status,
                                "severity": "MEDIUM"
                            })
        return vulnerabilities
