from datetime import date, datetime

import pytest

from src.dates import from_lms, to_lms_date, to_lms_datetime, validate_date_order

INPUTS = [
    "2026-08-01",
    "2026-08-01T00:00:00",
    "2026-08-01T00:00:00.000Z",
    "2026-08-01 00:00:00",
    "2026-08-31T23:59:59",
    "2000-01-01T00:00:00",
    "2022-02-22T22:22:22",
    "11-11-2011 11:11:11",
    date(2026, 8, 1),
    date(2000, 1, 1),
    datetime(2026, 9, 21, 0, 0, 0),
    datetime(2026, 9, 21, 23, 59, 59),
    datetime(1999, 12, 31, 11, 11, 11),
]


@pytest.mark.parametrize("value", INPUTS)
def test_to_lms_datetime_format(value):
    result = to_lms_datetime(value)
    assert result.endswith(".000Z")
    datetime.strptime(result, "%Y-%m-%dT%H:%M:%S.000Z")


@pytest.mark.parametrize("value", INPUTS)
def test_to_lms_datetime_trailing_char_is_unique(value):
    """The upstream globally replaces the last char before parsing - it must occur once."""
    result = to_lms_datetime(value)
    last_char = result[-1]
    assert result.count(last_char) == 1


@pytest.mark.parametrize("value", INPUTS)
def test_to_lms_date_format(value):
    result = to_lms_date(value)
    assert datetime.strptime(result, "%Y-%m-%d").strftime("%Y-%m-%d") == result


def test_to_lms_date_is_date_only():
    assert to_lms_date("2026-08-01T13:45:00") == "2026-08-01"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("18-09-2026 19:41:21", datetime(2026, 9, 18, 19, 41, 21)),
        ("01-01-2000 00:00:00", datetime(2000, 1, 1, 0, 0, 0)),
    ],
)
def test_from_lms_parses_response_format(raw, expected):
    assert from_lms(raw) == expected


@pytest.mark.parametrize(
    "dt",
    [
        datetime(2026, 8, 1, 0, 0, 0),
        datetime(2026, 8, 31, 23, 59, 59),
        datetime(2000, 1, 1, 11, 11, 11),
    ],
)
def test_round_trip_through_from_lms(dt):
    response_str = dt.strftime("%d-%m-%Y %H:%M:%S")
    assert from_lms(response_str) == dt


@pytest.mark.parametrize("garbage", ["not-a-date", "", "2026-13-45", "tomorrow", None, 12345])
def test_garbage_input_rejected(garbage):
    with pytest.raises((ValueError, TypeError)):
        to_lms_datetime(garbage)
    with pytest.raises((ValueError, TypeError)):
        to_lms_date(garbage)


def test_from_lms_rejects_wrong_format():
    with pytest.raises(ValueError):
        from_lms("2026-09-18T19:41:21.000Z")


def test_validate_date_order():
    validate_date_order("2026-09-01", "2026-09-21")
    validate_date_order("2026-09-21T10:00:00", "2026-09-21")
    with pytest.raises(ValueError, match="start_date"):
        validate_date_order("2026-09-22", "2026-09-21", from_name="start_date", to_name="end_date")
