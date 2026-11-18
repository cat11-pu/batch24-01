import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import oauth_guard


@pytest.fixture(autouse=True)
def reset_oauth_replay_state():
    oauth_guard._reset_replay_state()
