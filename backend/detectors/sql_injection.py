import ast
import re
from backend.core.vulnerability_scorer import VulnerabilityScorer

class SQLInjectionDetector:
    """
    Détecteur d'injection SQL avec analyse de flux
    """
    def __init__(self):
        self.dangerous_sql_functions = [
            'execute', 'query', 'cursor.execute', 'cursor.query',
            'mysqli_query', 'mysql_query', 'sqlite3.execute',
            'db.execute', 'connection.execute'
        ]
        self.sql_patterns = [
            r'SELECT.*FROM.*WHERE.*=.*\\+',
            r'INSERT.*VALUES.*\\+',
            r'UPDATE.*SET.*=.*\\+',
            r'DELETE.*WHERE.*=.*\\+',
        ]
        self.scorer = VulnerabilityScorer()

    def analyze_sql_injection(self, source_code):
        tree = ast.parse(source_code)
        vulnerabilities = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                vuln = self._check_sql_call(node, source_code)
                if vuln: vulnerabilities.append(vuln)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                vuln = self._check_sql_concatenation(node, source_code)
                if vuln: vulnerabilities.append(vuln)
        return vulnerabilities

    def _check_sql_call(self, node, source_code):
        func_name = self._get_function_name(node.func)
        if any(d in func_name.lower() for d in self.dangerous_sql_functions):
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    evidence = {
                        "direct_pattern_match": True,
                        "dangerous_function": True,
                        "user_input_flow": self._traces_user_input(arg),
                        "context_complete": True,
                        "sanitization_missing": not self._has_sanitization(source_code)
                    }
                    score = self.scorer.calculate_confidence_score(evidence)
                    status, _ = self.scorer.interpret_score(score)
                    return {
                        "type": "SQL_INJECTION",
                        "line": node.lineno,
                        "function": func_name,
                        "evidence": evidence,
                        "description": f"Injection SQL potentielle via concaténation dans {func_name}",
                        "severity": "HIGH",
                        "confidence_score": score,
                        "confidence_status": status
                    }
        return None

    def _check_sql_concatenation(self, node, source_code):
        try:
            left = self._node_to_string(node.left)
            right = self._node_to_string(node.right)
            combined = f"{left} + {right}"
            for pattern in self.sql_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    evidence = {
                        "direct_pattern_match": True,
                        "user_input_flow": True,
                        "dangerous_function": False,
                        "context_complete": False,
                        "sanitization_missing": True
                    }
                    score = self.scorer.calculate_confidence_score(evidence)
                    status, _ = self.scorer.interpret_score(score)
                    return {
                        "type": "SQL_INJECTION",
                        "line": node.lineno,
                        "pattern": pattern,
                        "description": f"Pattern d'injection SQL détecté: {combined}",
                        "severity": "HIGH",
                        "confidence_score": score,
                        "confidence_status": status
                    }
        except:
            pass
        return None

    def _get_function_name(self, func_node):
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            return f"{self._get_function_name(func_node.value)}.{func_node.attr}"
        return ""

    def _node_to_string(self, node):
        if isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        return ""

    def _traces_user_input(self, node):
        user_input_vars = ['input', 'request', 'params', 'args', 'form']
        return any(v in self._node_to_string(node).lower() for v in user_input_vars)

    def _has_sanitization(self, source_code):
        for p in ['escape', 'sanitize', 'clean', 'validate', 'prepare']:
            if p in source_code.lower():
                return True
        return False
