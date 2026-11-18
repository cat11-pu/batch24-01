import pytest

from smuggling_guard import validate

BAD_VALUES = [
  [
    [
      "Content-Length",
      "5"
    ],
    [
      "Transfer-Encoding",
      "chunked"
    ]
  ],
  [
    [
      "Content-Length",
      "5"
    ],
    [
      "Content-Length",
      "6"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "chunked"
    ],
    [
      "Transfer-Encoding",
      "identity"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "chunked"
    ],
    [
      "Content-Length",
      "5"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "chunked, identity"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "xchunked"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      " chunked"
    ]
  ],
  [
    [
      "Content-Length",
      "-1"
    ]
  ],
  [
    [
      "Content-Length",
      "abc"
    ]
  ],
  [
    [
      "Content-Length",
      "5, 6"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "chunked\r\n"
    ]
  ],
  [
    [
      "Content-Length",
      "5\u0000"
    ]
  ],
  [],
  [
    [
      "Host",
      "a"
    ],
    [
      "Content-Length",
      "5"
    ],
    [
      "Transfer-Encoding",
      "chunked"
    ]
  ],
  [
    [
      "Transfer-Encoding",
      "identity"
    ],
    [
      "Content-Length",
      "5"
    ]
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
