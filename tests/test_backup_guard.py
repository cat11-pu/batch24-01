import pytest

from backup_guard import validate

BAD_VALUES = [
  "/config.php.bak",
  "/.env.old",
  "/.git/config",
  "/index.php~",
  "/db.sql.gz",
  "/backup.zip",
  "/web.config.orig",
  "/.svn/entries",
  "/app.py.swp",
  "/APP.PHP.BAK",
  "/config%2ephp%2ebak",
  "/backup/..%2f.env",
  "/db.dump",
  "/site.tar.gz",
  "/config.php.save"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
