import pytest

from yaml_guard import validate

BAD_VALUES = [
  "!!python/object:os.system 'id'",
  "!!python/name:os.system",
  "!!python/object/apply:os.system ['id']",
  "a: &x [*x]",
  "a: &x {b: *x}",
  "- &a [*a]",
  "a: !!binary abc",
  "a: !!set {b: None}",
  "a: !!omap [{b: 1}]",
  "a: NaN0NaN",
  "",
  "not yaml",
  "a: !!python/module:os",
  "a: !!python/object/new:os.system ['id']",
  "a: &x 1\nb: *x"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
