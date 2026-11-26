import datetime as dt

from medveil.link import link
from medveil.model import Evidence, Record

REF = dt.date(2026, 6, 1)


def rec(**kw):
    r = Record(loc="doc")
    ev = Evidence()
    for k, v in kw.items():
        cur = getattr(ev, k)
        if isinstance(cur, set):
            cur |= set(v)
        else:
            cur.extend(v)
    r.ev = ev
    r.dates = [REF]
    return r


def same(clusters, i, j):
    return any(i in m and j in m for m in clusters.values())


def test_shared_uhid_links():
    rs = [rec(ids=[("mrn", "HSP26001")], names=[("rohit", "saksena")]),
          rec(ids=[("mrn", "HSP26001")], mentions=[("rohit",)])]
    assert same(link(rs, REF), 0, 1)


def test_homonyms_stay_apart():
    rs = [rec(ids=[("mrn", "A1")], names=[("haris", "pande")], ages=[21], villages=[("amarganj",)], relatives=[("vijay", "pande")]),
          rec(ids=[("mrn", "A2")], names=[("haris", "pande")], ages=[59], villages=[("jalalpur",)], relatives=[("arjun", "kumar")]),
          rec(names=[("haris", "pande")], ages=[21], villages=[("amarganj",)])]
    c = link(rs, REF)
    assert not same(c, 0, 1)
    assert same(c, 0, 2)


def test_shared_family_phone_does_not_merge():
    rs = [rec(phones=["9876543210"], names=[("sunita", "mehra")], genders=["F"]),
          rec(phones=["9876543210"], names=[("rakes", "mehra")], genders=["M"])]
    assert not same(link(rs, REF), 0, 1)


def test_fragment_links_only_when_unique():
    anchor = rec(ids=[("mrn", "B1")], names=[("mera", "saksena")], relatives=[("rajan", "saksena")])
    frag = rec(mentions=[("mera",)], relatives=[("rajan",)])
    assert same(link([anchor, frag], REF), 0, 1)
    other = rec(ids=[("mrn", "B2")], names=[("mera", "verma")], relatives=[("rajan", "verma")])
    assert not same(link([anchor, other, frag], REF), 0, 2)


def test_conflicting_aadhaar_blocks_merge():
    rs = [rec(ids=[("mrn", "C1"), ("aadhaar", "111122223333")], names=[("pooja", "mehra")]),
          rec(ids=[("aadhaar", "999988887777")], names=[("pooja", "mehra")], dobs=[dt.date(1990, 1, 1)]),
          rec(ids=[("mrn", "C1")], dobs=[dt.date(1990, 1, 1)])]
    c = link(rs, REF)
    assert not same(c, 0, 1) or not same(c, 1, 2)


def test_multi_patient_record_is_not_linked():
    rs = [rec(ids=[("mrn", "JJH1"), ("mrn", "JJH2")]), rec(ids=[("mrn", "JJH1")])]
    c = link(rs, REF)
    assert not any(0 in m for m in c.values())
