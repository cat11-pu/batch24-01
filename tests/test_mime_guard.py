import pytest

from mime_guard import validate

BAD_VALUES = [
  [
    "a.png",
    "text/html",
    "PNG"
  ],
  [
    "a.png",
    "image/png",
    "MZ"
  ],
  [
    "a.jpg",
    "image/png",
    "JPEG"
  ],
  [
    "a.png",
    "image/png",
    ""
  ],
  [
    "a.png",
    "image/png",
    "GIF89a"
  ],
  [
    "../a.png",
    "image/png",
    "PNG"
  ],
  [
    "a.png\u0000.jpg",
    "image/png",
    "PNG"
  ],
  [
    "a.png",
    "image/png\n",
    "PNG"
  ],
  [
    "a.png",
    "image/png",
    "P"
  ],
  [
    "a.png",
    "",
    "PNG"
  ],
  [
    "",
    "image/png",
    "PNG"
  ],
  [
    "a.png.exe",
    "image/png",
    "PNG"
  ],
  [
    "a.png",
    "image/jpeg",
    "PNG"
  ],
  [
    "a.svg",
    "image/svg+xml",
    "SVG"
  ],
  [
    "NaN.png",
    "image/png",
    "PNG"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
