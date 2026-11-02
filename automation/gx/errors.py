"""Exceptions shared by the gx modules. Their messages are shown to the operator as-is."""


class ConfigError(Exception):
    """The configuration is incomplete or breaks a dev/prod guard rail."""


class SignerError(Exception):
    """The signing backend cannot be used (key missing or unsupported, backend not implemented)."""


class StepError(Exception):
    """A step cannot continue."""


class Aborted(Exception):
    """The operator chose to quit."""
