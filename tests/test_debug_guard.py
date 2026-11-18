import pytest

from debug_guard import validate

BAD_VALUES = [
  "/debug",
  "/actuator/env",
  "/.env",
  "/metrics",
  "/DEBUG",
  "/Actuator/Env",
  "/%2eenv",
  "/debug/",
  "//debug",
  "/debug;.css",
  "/actuator//env",
  "/env",
  "/config",
  "/debug%00",
  "/debug/..;/env"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
