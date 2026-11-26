"""Vocabularies used by the detectors.

Everything here is generic domain knowledge (clinical words, Hindi function words,
Indian honorifics and relation markers, administrative names). No entry comes from
the practice dataset's patients.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

from .translit import key

DATA = Path(__file__).resolve().parent / "lexicon_data"


def _words(s: str) -> frozenset[str]:
    return frozenset(w.strip().lower() for w in s.split() if w.strip())


# Honorifics that follow a name ("Shahid sahab", "Asha ji", "Kamal Bhaiya").
HONORIFIC_POST = _words("""
ji jee sahab saheb sahib saab bhai bhaiya bhaiyya bhayya behenji behen bahen bahenji didi amma ammi
chacha chachi mausi mausa mama mami kaka kaki babu baba dada dadi nana nani bibi bhabhi bhabi
tai tau uncle aunty auntie maaji mataji pitaji bitiya
""")
HONORIFIC_POST_DEVA = frozenset("जी साहब साहिब भाई भैया बहनजी बहन दीदी अम्मा चाचा चाची मौसी मामा बाबू बाबा दादा दादी".split())

# Titles before a name.
HONORIFIC_PRE = _words("shri shree sri smt smt. srimati shrimati sushri km km. kumari mr mr. mrs mrs. ms ms. miss late master baby sh sh.")
NAME_PREFIX = _words("md md. mohd mohd. mohammad mohammed muhammad syed sayyed mirza sheikh shaikh")
HONORIFIC_PRE_DEVA = frozenset("श्री श्रीमती सुश्री कुमारी स्व. स्वर्गीय".split())

# Name parts the scorer itself treats as non-identifying on their own.
GENERIC_NAME_TOKENS = _words("devi kumar kumari md md. mohd mohd. mohammad ji bano begum khatoon khatun singh kaur bibi lal prasad ram")

# Hinglish postpositions that follow a name: "Irfan ka BP", "Anita behenji ka BP".
HINDI_POSTPOSITIONS = _words("ka ki ke ko ne se")
DEVA_POSTPOSITIONS = frozenset("को का की के ने से".split())

# Relation words in Devanagari.
DEVA_RELATION = frozenset("पुत्र पुत्री पत्नी पति सुपुत्र सुपुत्री बेटा बेटी".split())

# Complaint vocabulary: after "C/O" these mean "complaint of", not "care of".
COMPLAINT_WORDS = _words("""
fever pain cough cold vomiting vomiting, loose loose-motion motions stools diarrhoea diarrhea
headache giddiness dizziness breathlessness breathless burning micturition weakness generalised
generalized body ache aches abdomen abdominal chest swelling itching rash bleeding nausea
palpitation palpitations fatigue tiredness sore throat difficulty dysuria jaundice yellowish
constipation fits seizure seizures unconsciousness unconscious fall injury trauma bite snake dog
burns burn wound ulcer discharge irritation redness blurring blurred vision decreased loss
reduced poor appetite weight anorexia sweating chills rigors high grade low grade mild severe
acute chronic sudden on off intermittent continuous recurrent pedal edema oedema joint joints
back knee neck shoulder ear eye eyes tooth dental hiccups hematuria haematuria hemoptysis
haemoptysis epistaxis bukhar khansi dard ulti dast chakkar sir pet
""")

# Clinical and document words that look like names when capitalized.
CLINICAL_WORDS = _words("""
patient pt patients admitted admission discharge discharged summary diagnosis diagnosed history
complaints complaint presenting course hospital treated treatment conservatively condition stable
medications medication medicine medicines advice advised review reviewed opd ipd ward bed
consultant doctor dr nurse nursing notes note report reports lab laboratory pathology diagnostics
investigation investigations result results sample samples test tests value values unit units
range reference normal abnormal high low positive negative pending approved settled rejected
procedure surgery operation done day days week weeks month months year years yrs yr hours hrs
morning evening night next previous follow followup follow-up visit visits date time age sex
gender male female name address mobile phone contact uhid mrn reg no registration relation
relative attendant guardian informed diet salt diabetic low continue stop start tab tablet cap
capsule inj injection syp syrup sachet drops oint ointment inhaler iv im sc po bd tds od hs sos
qid stat prn x mg mcg ml gm g kg iu units bp pulse temp spo2 rbs fbs ppbs hb hba1c tsh wbc rbc
plt esr crp lft kft rft ecg echo xray x-ray usg ct mri chest blood sugar random fasting serum
creatinine urea sodium potassium haemoglobin hemoglobin platelet count total differential
typhoid malaria dengue tuberculosis tb pneumonia anaemia anemia hypertension diabetes asthma
copd infection fever urinary tract acute chronic kidney disease disorder syndrome essential
primary secondary unspecified without with complications site specified type mellitus
cataract hernia appendicitis cholecystitis gastroenteritis colitis bronchitis jaundice hepatitis
covid rabies leishmaniasis kala-azar kala azar hypothyroidism thyroid heart failure stroke
medicine surgery pulmonology neurology cardiology orthopaedics orthopedics paediatrics pediatrics
gynaecology obstetrics ent ophthalmology dermatology psychiatry emergency casualty icu nicu
general department multispeciality multispecialty charitable district hospital clinic centre
center sadan seva aspatal dispensary phc chc trust nursing home diagnostic diagnostics labs
forwarded attachment pdf jpg image report received from referred refer referral by to of the
and or in on at for a an is was has had be been are were will shall may can should must not no
yes ok okay please kindly thanks thank regards dear sir madam team staff clerk system export
module records record clean protocol formulary census version consent form surgical witnessed
witness signature sign signed helpdesk ticket billing query closed open status category trip
ambulance oxygen given en route called round evening rounds took log visitor visitors
anm aww worker workers anganwadi
""")

# Generic drug names and brands common in Indian prescriptions.
DRUGS = _words("""
paracetamol dolo crocin calpol pcm ibuprofen diclofenac aceclofenac nimesulide tramadol aspirin
ecosprin clopidogrel atorvastatin rosuvastatin amlodipine telmisartan losartan olmesartan ramipril
enalapril metoprolol atenolol propranolol carvedilol furosemide lasix torsemide spironolactone
hydrochlorothiazide metformin glimepiride gliclazide glipizide sitagliptin vildagliptin teneligliptin
insulin glargine actrapid mixtard levothyroxine thyronorm eltroxin carbimazole pantoprazole pan
omeprazole rabeprazole esomeprazole ranitidine famotidine domperidone ondansetron metoclopramide
azithromycin amoxicillin augmentin amoxyclav cefixime ceftriaxone cefuroxime cefpodoxime
ciprofloxacin ofloxacin levofloxacin norfloxacin metronidazole tinidazole doxycycline
nitrofurantoin cotrimoxazole linezolid vancomycin meropenem piperacillin tazobactam gentamicin
amikacin artesunate artemether lumefantrine chloroquine primaquine quinine rifampicin isoniazid
pyrazinamide ethambutol akt att fluconazole albendazole ivermectin acyclovir oseltamivir
salbutamol levosalbutamol asthalin budesonide formoterol montelukast cetirizine levocetirizine
fexofenadine chlorpheniramine prednisolone methylprednisolone dexamethasone hydrocortisone
ors zinc iron ferrous sulphate sulfate folic acid calcium vitamin vit b12 d3 multivitamin
levodopa carbidopa syndopa trihexyphenidyl phenytoin levetiracetam valproate carbamazepine
clonazepam alprazolam diazepam lorazepam amitriptyline sertraline escitalopram fluoxetine
haloperidol olanzapine risperidone quetiapine penicillin benzathine streptokinase heparin
enoxaparin warfarin digoxin nitroglycerin isosorbide dinitrate mononitrate frusemide
mannitol dextrose saline ringer lactate rl ns dns potassium chloride sodium bicarbonate
lactulose bisacodyl liquid paraffin ursodeoxycholic udca silymarin thiamine pyridoxine
glycopyrrolate atropine adrenaline noradrenaline dopamine dobutamine lignocaine lidocaine
penicillamine zinc deferasirox anti-rabies arv rabies vaccine tt tetanus toxoid immunoglobulin
liposomal amphotericin miltefosine sodium stibogluconate
""")

# Hindi words (Devanagari) that are not names.
HINDI_COMMON = frozenset("""
मरीज़ मरीज रोगी मरीज़ा उसे उन्हें इन्हें इसे यह वह ये वो और या में से को का की के ने पर तक
है हैं था थी थे हो गया गई गए दिन दिनों सप्ताह हफ्ते महीने साल वर्ष बुखार दर्द पेट सिर खांसी
उल्टी दस्त चक्कर कमजोरी कमज़ोरी सांस जलन पेशाब दवा दवाई दवाएं जांच इलाज भर्ती छुट्टी तारीख
निदान डिस्चार्ज सारांश पर्चा ओपीडी नाम आयु उम्र लिंग पता मोबाइल पुरुष महिला पिता पति माता पत्नी
पुत्र पुत्री ग्राम गांव गाँव तहसील जिला ज़िला राज्य मकान नं मोहल्ला के पास पीछे सामने वार्ड
अस्पताल डॉक्टर डॉ सलाह समीक्षा बाद फिर से कम ज्यादा ज़्यादा बहुत ठीक स्थिर हालत अब भी
पंजीकरण सं आईपीडी नंबर संख्या पिन कोड टाइप डायबिटीज़ मधुमेह उच्च रक्तचाप निमोनिया मलेरिया
टाइफाइड डेंगू क्षय रोग टीबी काला-अज़ार दमा रेबीज़ और साथ कोई समस्या हो तो कॉल करें करो
फेफड़ों फेफड़े फेफड़ा पीलिया हैजा खसरा चेचक कैंसर गुर्दे गुर्दा हृदय दिल लिवर किडनी सर्दी जुकाम दौरा
मिर्गी थायराइड एनीमिया खून कमी पथरी संक्रमण मूत्र मार्ग घाव चोट हड्डी जोड़ों घुटने कमर गले आंख कान
नाक दांत त्वचा एलर्जी उच्च निम्न सामान्य रिपोर्ट परीक्षण नमूना मात्रा गोली इंजेक्शन सिरप सुबह शाम रात
दोपहर खाने पहले बाद रोज़ रोज बार प्रतिदिन लगातार हल्का तेज़ तेज मरीज़ों परिवार घर वापस जाएं आएं
""".split())

# Header lexicon: normalized header tokens to semantic type. Order matters.
HEADER_RULES: list[tuple[str, str]] = [
    (r"\b(doctor|dr|consultant|physician|surgeon|ref doctor|referred by|referring|treating|practitioner|author)\b", "DOCTOR"),
    (r"\b(relation|rel type|relationship)\b$", "RELATION"),
    (r"\b(pita|pati|father|husband|guardian|relative|attendant|nok|kin|spouse|mother|wife|son of|care of|informant|contact person|parent|mata)\b", "RELATIVE"),
    (r"\b(first ?name|given|fname|forename|pratham naam)\b", "FIRST_NAME"),
    (r"\b(last ?name|surname|family|lname|upnaam)\b", "LAST_NAME"),
    (r"\b(abha ?address|health ?id ?address|phr ?address)\b", "ABHA_ADDR"),
    (r"\b(abha|health ?id|healthid|ndhm|abdm)\b", "ABHA"),
    (r"\b(aadhaar|aadhar|adhaar|adhar|aadhaar no|uidai|uid no)\b", "AADHAAR"),
    (r"\b(pan|pan no|pan card|payer pan)\b", "PAN"),
    (r"\b(pmjay|policy|insurance|insurer id|member id|card no|ayushman|beneficiary|tpa id|scheme id)\b", "INSURANCE"),
    (r"\b(e ?mail|email id|mail)\b", "EMAIL"),
    (r"\b(mobile|phone|contact|mob|cell|tel|telephone|callback|whatsapp|ph no|contact no)\b", "PHONE"),
    (r"\b(uhid|mrn|mr no|mrd|patient ?id|patientid|pid|reg no|regn no|registration no|reg number|cr no|crno|ipd ?no|ip ?no|ipd|admission no|adm no|hospital no|patient ref|patient_ref|hosp id|patient no|case no|bht)\b", "MRN"),
    (r"\b(dob|d o b|date of birth|birth ?date|birthdate|janm|janm tithi|born)\b", "DOB"),
    (r"\b(age ?sex|age ?gender|age ?/ ?sex)\b", "AGE_SEX"),
    (r"\b(age|umar|umra|umr|aayu|aayu varsh)\b", "AGE"),
    (r"\b(gender|sex|ling)\b", "GENDER"),
    (r"\b(pin|pincode|pin code|zip|postal|postcode|post code)\b", "PIN"),
    (r"\b(village|gaon|gram|mohalla|city|town|basti|locality|ward no|colony|gali)\b", "VILLAGE"),
    (r"\b(tehsil|taluk|taluka|block|sub ?district|tahsil)\b", "TEHSIL"),
    (r"\b(district|jila|zila|distt|dist)\b", "DISTRICT"),
    (r"\b(state|rajya)\b", "STATE"),
    (r"\b(address|pata|street|addr|house|residence|line)\b", "ADDRESS"),
    (r"\b(patient name|patient s name|pt name|name of patient|rogi ka naam|mariz ka naam|naam|name|nam|patient|beneficiary name|full name|raised by)\b", "NAME"),
    (r"\b(note|notes|remark|remarks|comment|comments|history|complaint|complaints|advice|description|narrative|details|summary|text)\b", "TEXT"),
    (r"\b(date|dt|on|tithi|tarikh|time|timestamp|collected|reported|admitted|discharged|visit|registered)\b", "DATE"),
]

# Devanagari header words.
DEVA_HEADER = {
    "नाम": "NAME", "मरीज़ का नाम": "NAME", "मरीज का नाम": "NAME", "रोगी का नाम": "NAME",
    "पिता का नाम": "RELATIVE", "पति का नाम": "RELATIVE", "पिता/पति का नाम": "RELATIVE",
    "आयु": "AGE", "उम्र": "AGE", "लिंग": "GENDER", "जन्म तिथि": "DOB", "पता": "ADDRESS",
    "ग्राम": "VILLAGE", "गांव": "VILLAGE", "गाँव": "VILLAGE", "तहसील": "TEHSIL", "जिला": "DISTRICT",
    "ज़िला": "DISTRICT", "पिन कोड": "PIN", "पिन": "PIN", "मोबाइल": "PHONE", "मोबाइल नं": "PHONE",
    "आधार": "AADHAAR", "पंजीकरण सं": "MRN", "पंजीकरण संख्या": "MRN", "तारीख": "DATE", "दिनांक": "DATE",
}

# JSON / FHIR keys that are never PII containers.
SAFE_KEYS = _words("""
resourcetype id fullurl reference system code display status type unit units loinc test value
valuequantity range interpretation category department drug strength frequency duration form
route dose rx diagnosis package_code package procedure amount amount_inr bill_no visit_id
sample_id panels results result lab report_type schema profile version use rank lastupdated
coding class priority intent subject_reference encounter_reference
""")

GENDER_WORDS = {
    "m": "M", "male": "M", "man": "M", "पुरुष": "M", "f": "F", "female": "F", "woman": "F",
    "महिला": "F", "स्त्री": "F", "o": "O", "other": "O", "t": "O",
}


@lru_cache(maxsize=1)
def _names() -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    given = [l.strip() for l in (DATA / "given_names.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    sur = [l.strip() for l in (DATA / "surnames.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    stop = CLINICAL_WORDS | DRUGS | COMPLAINT_WORDS
    g = frozenset(x.lower() for x in given if x.lower() not in stop)
    s = frozenset(x.lower() for x in sur if x.lower() not in stop)
    gk = frozenset(key(x) for x in g if len(key(x)) >= 2)
    sk = frozenset(key(x) for x in s if len(key(x)) >= 2)
    return g, s, gk, sk


def is_given(tok: str) -> bool:
    g, _, gk, _ = _names()
    return tok.lower() in g or key(tok) in gk


def is_surname(tok: str) -> bool:
    _, s, _, sk = _names()
    return tok.lower() in s or key(tok) in sk


def is_name_token(tok: str) -> bool:
    return is_given(tok) or is_surname(tok)


def is_stopword(tok: str) -> bool:
    t = tok.lower().strip(".,:;()")
    return t in CLINICAL_WORDS or t in DRUGS or t in COMPLAINT_WORDS or t in HINDI_COMMON


@lru_cache(maxsize=1)
def districts() -> dict[str, tuple[str, str]]:
    """Folded district name (Latin or Devanagari) -> (canonical Latin, division)."""
    out: dict[str, tuple[str, str]] = {}
    with open(DATA / "districts.tsv", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            canon = row["district"].strip()
            div = row["division"].strip()
            for variant in (canon, row["deva"].strip(), canon.replace(" ", "")):
                out[variant.lower()] = (canon, div)
    return out


def district_of(text: str) -> tuple[str, str] | None:
    t = " ".join(text.lower().split())
    t = t.replace("distt.", "").replace("district", "").replace("जिला", "").strip(" .,-")
    d = districts()
    if t in d:
        return d[t]
    if t.replace(" ", "") in d:
        return d[t.replace(" ", "")]
    return None
