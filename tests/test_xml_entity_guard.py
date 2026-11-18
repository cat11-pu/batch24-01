import pytest

from xml_entity_guard import validate

BAD_VALUES = [
  "<!DOCTYPE root [<!ENTITY x 'y'>]><root>&x;</root>",
  "<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><root>&x;</root>",
  "<!DOCTYPE root [<!ENTITY a 'lol'><!ENTITY b '&a;&a;&a;'>]><root>&b;</root>",
  "<!DOCTYPE root [<!ENTITY % p SYSTEM 'http://evil'>]><root/>",
  "<!DOCTYPE root SYSTEM 'http://evil/evil.dtd'><root/>",
  "<!DOCTYPE root [<!ENTITY x 'y'>]><root/>",
  "<root>&xxe;</root>",
  "<!DOCTYPE root [<!ELEMENT root ANY>]><root/>",
  "<!DOCTYPE root [<!ATTLIST root x CDATA 'y'>]><root/>",
  "<!DOCTYPE root [<!NOTATION n SYSTEM 'x'>]><root/>",
  "",
  "not xml",
  "<root>\u0000</root>",
  "<!DOCTYPE root [<!ENTITY x 'y'>]><root>&x;&x;&x;</root>",
  "<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><root/>"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
