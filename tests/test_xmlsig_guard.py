import pytest

from xmlsig_guard import validate

BAD_VALUES = [
  "<root><Signature>bad</Signature></root>",
  "<root ID='a'><Signature Reference='#b'/></root>",
  "<root ID='a' ID='b'><Signature Reference='#a'/></root>",
  "<wrapper><root ID='a'><Signature Reference='#a'/></root></wrapper>",
  "<root><Signature/><Signature/></root>",
  "<root ID='a'><Signature Reference='#a'><Object ID='a'/></Signature></root>",
  "<root><Signature Reference=''/></root>",
  "<root><Signature Reference='#missing'/></root>",
  "<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><root>&x;</root>",
  "<root><Signature Reference='#a'/><a ID='b'/></root>",
  "",
  "not xml",
  "<root><Signature Reference='#a'/><a ID='a'/><b ID='a'/></root>",
  "<root><Signature Reference='#a'/><a ID='a'><Signature/></a></root>",
  "<root><Signature Reference='#a'/><a ID='a'><x/></a></root>"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
