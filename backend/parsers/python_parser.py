import ast

def parse_python_code(file_path: str = None, source_code: str = None):
    """
    Parse un fichier Python ou du code source et renvoie les noms de toutes les 
    fonctions, classes et variables présentes.
    """
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
    elif not source_code:
        raise ValueError("Il faut fournir soit file_path soit source_code")
    
    tree = ast.parse(source_code)
    
    functions = []
    classes = []
    variables = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variables.append(target.id)

    return {
        "functions": functions, 
        "classes": classes,
        "variables": variables
    }
