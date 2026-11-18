import pytest

from unicode_guard import validate

BAD_VALUES = [
  "..／etc/passwd",
  "..∕etc/passwd",
  "..⁄etc/passwd",
  "..＼etc/passwd",
  "%ef%bc%8f..%ef%bc%8fetc",
  "..∕etc/passwd",
  "..⁄etc/passwd",
  "..⧸etc/passwd",
  "..∖etc/passwd",
  "..​etc/passwd",
  "..‮etc/passwd",
  "..⁦etc/passwd",
  "..%c0%afetc/passwd",
  "..%e0%80%afetc/passwd",
  "..․etc/passwd"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
