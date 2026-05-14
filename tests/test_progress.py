from vaultsieve.progress import PROGRESS_COUNTER_RE


def test_progress_counter_pattern_normalizes_repeated_updates() -> None:
    assert (
        PROGRESS_COUNTER_RE.sub("", "Checking Have I Been Pwned (1/272 unique passwords)")
        == "Checking Have I Been Pwned"
    )
    assert (
        PROGRESS_COUNTER_RE.sub("", "Checking credential domains (616/616 unique domains)")
        == "Checking credential domains"
    )
