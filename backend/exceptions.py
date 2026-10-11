"""Typed error hierarchy — every failure in Secura has a name."""


class SecuraError(Exception):
    """Base class for all Secura errors."""


class ValidationError(SecuraError):
    """The submitted target is malformed or unusable."""


class ScannerError(SecuraError):
    """A scanner failed while probing its target."""


class TargetNotReachable(ScannerError):
    """The target did not respond to the scanner."""


class AnalyzerError(SecuraError):
    """The AI analysis layer failed."""


class OllamaNotAvailable(AnalyzerError):
    """Ollama is not running or not reachable."""


class ReportNotFound(SecuraError):
    """A requested report id does not exist."""
