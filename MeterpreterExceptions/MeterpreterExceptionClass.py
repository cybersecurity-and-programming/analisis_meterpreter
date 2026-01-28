class MeterpreterError(Exception):
    """Error base de la herramienta."""
    pass

class FileMissingError(MeterpreterError):
    """Archivo no encontrado."""
    pass

class InvalidArgumentError(MeterpreterError):
    """Argumentos inválidos."""
    pass

class AnalysisError(MeterpreterError):
    """Error durante el análisis."""
    pass

class IncorrectLenghtKey(MeterpreterError):
    """Error en claves AES"""
    pass
