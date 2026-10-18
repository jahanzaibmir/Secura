"""Typed error hierarchy. Every failure Secura reports has a name and an HTTP status."""


class SecuraError(Exception):
    """Base class for all Secura errors."""

    status_code = 500


class ValidationError(SecuraError):
    """The submitted target or input is malformed or unusable."""

    status_code = 400


class NotFoundError(SecuraError):
    """A requested resource does not exist."""

    status_code = 404


class ReportNotFound(NotFoundError):
    """A requested report id does not exist."""


class JobNotFound(NotFoundError):
    """A requested scan job id does not exist."""


class CapacityError(SecuraError):
    """The scan queue is full."""

    status_code = 429


class ForbiddenError(SecuraError):
    """The operation is disabled by configuration."""

    status_code = 403


class SourceError(SecuraError):
    """Source code could not be acquired (clone failure, missing folder)."""

    status_code = 502


class EngineError(SecuraError):
    """A security engine failed while analysing source code."""


class ScanCancelled(SecuraError):
    """The scan was cancelled by the user."""

    status_code = 409


class AnalyzerError(SecuraError):
    """The AI explanation layer failed."""

    status_code = 400


class AnalyzerUnavailable(AnalyzerError):
    """The AI provider is not reachable or not ready."""
