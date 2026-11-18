import pytest

from cache_key_guard import validate

BAD_VALUES = [
  [
    [
      "Host",
      "evil.com"
    ]
  ],
  [
    [
      "X-Forwarded-Host",
      "evil.com"
    ]
  ],
  [
    [
      "X-Forwarded-Host",
      "app.example.com"
    ],
    [
      "Host",
      "evil.com"
    ]
  ],
  [
    [
      "Authorization",
      "Bearer x"
    ]
  ],
  [
    [
      "Cookie",
      "session=x"
    ]
  ],
  [
    [
      "Accept-Language",
      "en"
    ]
  ],
  [
    [
      "X-User",
      "admin"
    ]
  ],
  [
    [
      "Host",
      "app.example.com\r\n"
    ]
  ],
  [
    [
      "Host",
      ""
    ]
  ],
  [
    [
      "Host",
      "APP.EXAMPLE.COM"
    ]
  ],
  [
    [
      "X-Forwarded-Proto",
      "http"
    ]
  ],
  [
    [
      "X-Forwarded-Port",
      "8443"
    ]
  ],
  [
    [
      "Host",
      "app.example.com:8443"
    ]
  ],
  [
    [
      "Host",
      "app.example.com"
    ],
    [
      "X-Forwarded-Host",
      "evil.com"
    ]
  ],
  [
    [
      "Host",
      "app.example.com.evil.com"
    ]
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
