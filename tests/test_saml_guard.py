import pytest

from saml_guard import validate

BAD_VALUES = [
  "<Response Audience='other' Recipient='https://app/cb'/>",
  "<Response Audience='app' Recipient='https://evil/cb'/>",
  "<Response NotOnOrAfter='2000-01-01T00:00:00Z'/>",
  "<Response NotBefore='2999-01-01T00:00:00Z'/>",
  "<Response><Assertion/><Assertion/></Response>",
  "<Response><Assertion><Signature/></Assertion></Response>",
  "<Response/>",
  "",
  "not xml",
  "<Response Audience='' Recipient=''/>",
  "<Response Audience='app' Recipient='https://app/cb'><Signature/></Response>",
  "<Response Audience='APP' Recipient='https://app/cb'/>",
  "<Response Audience='app' Recipient='http://app/cb'/>",
  "<Response Audience='app' Recipient='https://app/cb' NotOnOrAfter='bad'/>",
  "<Response><Assertion ID='a'/><Assertion ID='a'/></Response>"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
