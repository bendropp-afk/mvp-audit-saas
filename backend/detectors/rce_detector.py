import ast
from backend.core.vulnerability_scorer import VulnerabilityScorer

class RCEDetector:
    """
    Détecteur RCE : repère l’exécution dynamique de code (eval, exec, os.system, pickle.loads…).
    """
    def __init__(self):
        self.scorer = VulnerabilityScorer()
        self.dangerous_funcs = {
            "eval", "exec", "compile", "os.system", "subprocess.Popen",
            "pickle.loads", "yaml.load"
        }

    def analyze_rce(self, source_code: str):
        tree = ast.parse(source_code)
        vulnerabilities = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = ""
                if isinstance(node.func, ast.Name):
                    func = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func = f"{self._get_name(node.func.value)}.{node.func.attr}"
                if func in self.dangerous_funcs:
                    evidence = {
                        "direct_pattern_match": True,
                        "dangerous_function": True,
                        "user_input_flow": any(
                            isinstance(arg, ast.Name) and arg.id in ("input", "args", "data")
                            for arg in node.args
                        ),
                        "sanitization_missing": True
                    }
                    score = self.scorer.calculate_confidence_score(evidence)
                    status, _ = self.scorer.interpret_score(score)
                    vulnerabilities.append({
                        "type": "RCE",
                        "line": node.lineno,
                        "function": func,
                        "description": f"Appel dangereux détecté : {func}()",
                        "confidence_score": score,
                        "confidence_status": status,
                        "severity": "HIGH"
                    })
        return vulnerabilities

    def _get_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return ""
