import datetime as dt

import pytest

from medveil.detect.dates import find_dates, order_evidence, render
from medveil.privacy import shift_date


@pytest.mark.parametrize("text,order,expected", [
    ("Date of Admission: 07/02/2026", "dmy", dt.date(2026, 2, 7)),
    ("Registered 11/24/2025", "mdy", dt.date(2025, 11, 24)),
    ("visit 2026-05-20", "dmy", dt.date(2026, 5, 20)),
    ("chat [30/05/26, 9:32 pm]", "dmy", dt.date(2026, 5, 30)),
    ("discharge 26.10.2026", "dmy", dt.date(2026, 10, 26)),
    ("on 12-Apr-1977", "dmy", dt.date(1977, 4, 12)),
    ("on April 12, 1977", "dmy", dt.date(1977, 4, 12)),
    ("Visit: 5 September", "dmy", dt.date(2026, 9, 5)),
])
def test_parse(text, order, expected):
    hits = find_dates(text, order)
    assert hits and hits[0].date == expected


@pytest.mark.parametrize("text", ["07/02/2026", "2026-02-07T18:15:00+05:30", "7.2.2026", "07-Feb-2026",
                                  "Feb 7, 2026", "5 September", "30/05/26"])
def test_render_keeps_format_and_interval(text):
    h = find_dates(text, "dmy")[0]
    out = render(h, shift_date(h.date, 40))
    again = find_dates(out, "dmy")[0]
    assert (again.date - h.date).days == 40 or not h.has_year
    # same separators and the same component order as the input
    import re
    assert re.sub(r"\d", "9", out).replace("99", "9") == re.sub(r"\d", "9", text[h.start:h.end]).replace("99", "9") \
        or "September" in text or "Feb" in text


def test_mdy_render_roundtrip():
    h = find_dates("01/13/2026", "mdy")[0]
    out = render(h, shift_date(h.date, 3))
    assert out == "01/16/2026"


def test_iso_time_suffix_untouched():
    text = "2026-02-04T18:15:00+05:30"
    h = find_dates(text, "dmy")[0]
    new = render(h, shift_date(h.date, 1)) + text[h.end:]
    assert new == "2026-02-05T18:15:00+05:30"


def test_order_evidence():
    assert order_evidence("01/13/2026 and 02/28/2025") == (0, 2)
    assert order_evidence("13/01/2026") == (1, 0)


def test_ids_are_not_dates():
    assert not find_dates("OPD/26/01/00151 IP/26/00130 SNJ/26/064127 IPD-2026-00461", "dmy")
