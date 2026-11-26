import pytest

from medveil.translit import deva_to_latin, key, tokens_match


@pytest.mark.parametrize("deva,latin", [
    ("मोहम्मद", "Mohammad"), ("मोहम्मद", "Mohd."), ("मोहम्मद", "Md."), ("शाहिद", "Shahid"),
    ("कविता", "Kavita"), ("पांडे", "Pandey"), ("रमेश", "Ramesh"), ("कमला", "Kamla"),
    ("हरीश", "Harish"), ("मोहनगंज", "Mohanganj"), ("कलां", "Kalan"), ("सलमा", "Salma"),
    ("अंसारी", "Ansari"), ("ज़ैनब", "Zainab"), ("सुनीता", "Sunita"), ("पटेल", "Patel"),
])
def test_cross_script_keys_match(deva, latin):
    assert tokens_match(key(deva), key(latin))


@pytest.mark.parametrize("a,b", [("Reena", "Rina"), ("Hareesh", "Harish"), ("Choudhary", "Chaudhary"),
                                 ("Mohammed", "Muhammad"), ("Shyaam", "Shyam"), ("Fatma", "Fatima")])
def test_latin_variants_match(a, b):
    assert tokens_match(key(a), key(b))


@pytest.mark.parametrize("a,b", [("Ramesh", "Rajesh"), ("Sunita", "Savita"), ("Asha", "Usha"), ("Kamal", "Kamla")])
def test_different_names_do_not_match(a, b):
    assert not tokens_match(key(a), key(b))


def test_schwa_deletion():
    assert deva_to_latin("कमला") == "kamlaa"
    assert deva_to_latin("अमरगंज") == "amarganj"
    assert deva_to_latin("प्रकाश") == "prakaash"
    assert deva_to_latin("सलमान") == "salmaan"
    assert deva_to_latin("खुर्द") == "khurd"
    assert deva_to_latin("उपेंद्र") == "upendra"
    assert deva_to_latin("चंद्र") == "chandra"
