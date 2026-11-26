#!/usr/bin/env python3
"""Dev-only "unseen-format" variant generator for the Secret Wards practice data.

The hidden evaluation has a round with names, field labels, identifier and date formats
and column names that never appear in the practice files. This tool rewrites the
practice set into held-out variants and keeps the answer key (truth.json) consistent,
so the pipeline can be measured on formats it was not tuned on.

    python tools/chaos_gen.py --kit ../Secret-Wards-ToolKit --out chaos --seed 7
    python tools/chaos_gen.py --kit ../Secret-Wards-ToolKit --out chaos --seed 11 --variants names,headers,ids

Output: <out>/<seed>/input/... and <out>/<seed>/truth/truth.json (same schema as the
practice key). Every transformation is deterministic from --seed. Replacements are made
per file on decoded text, using the truth surfaces of that file, longest first; a surface
that cannot be found (or sits inside a protected doctor name / medical probe) is skipped
and counted. JSON string literals written with \\uXXXX escapes are edited on their decoded
value and written back escaped. The dates variant re-spells D/M/Y, M/D/Y and ISO dates in
text, CSV and TSV, and non-ISO DOB values in JSON (ISO stays ISO there). A patient's UHID in
the key changes only if that identifier was rewritten in at least one file. Input files
that truth.json does not describe are copied unchanged, with a warning count. Never
imported by the pipeline.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import csv
import hashlib
import io
import itertools
import json
import random
import re
import shutil
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import date
from difflib import SequenceMatcher
from pathlib import Path

ALL_VARIANTS = ("names", "labels", "ids", "dates", "phones", "headers", "canaries")
NAME_TYPES = ("PATIENT_NAME", "RELATIVE_NAME")
ADDRESS_TYPES = ("VILLAGE", "LOCALITY", "LANDMARK", "HOUSE")
MARKER = "chaos_meta.json"

# ---------------------------------------------------------------------------
# Bilingual name tables (Latin, Devanagari). Entries that occur anywhere in the
# practice data are dropped at run time, so the output only uses unseen names.
# ---------------------------------------------------------------------------
GIVEN_MALE = [
    ("Pradeep", "प्रदीप"), ("Sandeep", "संदीप"), ("Rajeev", "राजीव"), ("Sanjeev", "संजीव"),
    ("Naveen", "नवीन"), ("Pankaj", "पंकज"), ("Nitin", "नितिन"), ("Rohit", "रोहित"),
    ("Mohit", "मोहित"), ("Sachin", "सचिन"), ("Gaurav", "गौरव"), ("Saurabh", "सौरभ"),
    ("Vivek", "विवेक"), ("Ankit", "अंकित"), ("Ankur", "अंकुर"), ("Anuj", "अनुज"),
    ("Abhishek", "अभिषेक"), ("Ashish", "आशीष"), ("Alok", "आलोक"), ("Anand", "आनंद"),
    ("Arvind", "अरविंद"), ("Arun", "अरुण"), ("Bharat", "भरत"), ("Chandan", "चंदन"),
    ("Devendra", "देवेंद्र"), ("Dharmendra", "धर्मेंद्र"), ("Dilip", "दिलीप"), ("Ganesh", "गणेश"),
    ("Girish", "गिरीश"), ("Hemant", "हेमंत"), ("Jitendra", "जितेंद्र"), ("Kailash", "कैलाश"),
    ("Kamlesh", "कमलेश"), ("Lalit", "ललित"), ("Mahendra", "महेंद्र"), ("Manish", "मनीष"),
    ("Narendra", "नरेंद्र"), ("Pawan", "पवन"), ("Pramod", "प्रमोद"), ("Prashant", "प्रशांत"),
    ("Rajendra", "राजेंद्र"), ("Ravindra", "रवींद्र"), ("Satish", "सतीश"), ("Shailendra", "शैलेंद्र"),
    ("Shankar", "शंकर"), ("Sudhir", "सुधीर"), ("Surendra", "सुरेंद्र"), ("Tarun", "तरुण"),
    ("Uday", "उदय"), ("Upendra", "उपेंद्र"), ("Vinod", "विनोद"), ("Vishal", "विशाल"),
    ("Yogesh", "योगेश"), ("Kishore", "किशोर"), ("Lokesh", "लोकेश"), ("Mukund", "मुकुंद"),
    ("Nikhil", "निखिल"), ("Shashank", "शशांक"), ("Tushar", "तुषार"), ("Vinay", "विनय"),
    ("Yashpal", "यशपाल"), ("Bhupendra", "भूपेंद्र"), ("Jagmohan", "जगमोहन"), ("Hariom", "हरिओम"),
    ("Shivendra", "शिवेंद्र"), ("Rizwan", "रिज़वान"), ("Sohail", "सोहेल"), ("Nadeem", "नदीम"),
    ("Naeem", "नईम"), ("Wasim", "वसीम"), ("Shakeel", "शकील"), ("Tariq", "तारिक़"),
    ("Rashid", "रशीद"), ("Sajid", "साजिद"), ("Anwar", "अनवर"), ("Asif", "आसिफ़"),
    ("Junaid", "जुनैद"), ("Faisal", "फ़ैसल"), ("Adil", "आदिल"), ("Shoaib", "शोएब"),
    ("Danish", "दानिश"), ("Kamran", "कामरान"), ("Iqbal", "इक़बाल"), ("Mushtaq", "मुश्ताक़"),
    ("Altaf", "अल्ताफ़"), ("Sarfaraz", "सरफ़राज़"), ("Ehsan", "एहसान"), ("Gurmeet", "गुरमीत"),
    ("Harbhajan", "हरभजन"), ("Paramjit", "परमजीत"), ("Balbir", "बलबीर"), ("Jaswant", "जसवंत"),
    ("Gurdeep", "गुरदीप"), ("Amarjeet", "अमरजीत"), ("Kulwant", "कुलवंत"), ("Thomas", "थॉमस"),
    ("Samuel", "सैमुअल"), ("Francis", "फ्रांसिस"), ("Daniel", "डेनियल"),
]
GIVEN_FEMALE = [
    ("Priya", "प्रिया"), ("Preeti", "प्रीति"), ("Neelam", "नीलम"), ("Nisha", "निशा"),
    ("Anjali", "अंजलि"), ("Archana", "अर्चना"), ("Babita", "बबीता"), ("Bhawna", "भावना"),
    ("Deepika", "दीपिका"), ("Divya", "दिव्या"), ("Jyoti", "ज्योति"), ("Kajal", "काजल"),
    ("Kalpana", "कल्पना"), ("Kusum", "कुसुम"), ("Lata", "लता"), ("Madhu", "मधु"),
    ("Mamta", "ममता"), ("Meenakshi", "मीनाक्षी"), ("Monika", "मोनिका"), ("Nirmala", "निर्मला"),
    ("Poonam", "पूनम"), ("Pratibha", "प्रतिभा"), ("Rachna", "रचना"), ("Rajni", "रजनी"),
    ("Ranjana", "रंजना"), ("Rashmi", "रश्मि"), ("Renu", "रेनू"), ("Ritu", "रितु"),
    ("Sadhana", "साधना"), ("Sangeeta", "संगीता"), ("Sapna", "सपना"), ("Savita", "सविता"),
    ("Seema", "सीमा"), ("Shalini", "शालिनी"), ("Shobha", "शोभा"), ("Sudha", "सुधा"),
    ("Sushma", "सुषमा"), ("Swati", "स्वाति"), ("Vimla", "विमला"), ("Anuradha", "अनुराधा"),
    ("Hemlata", "हेमलता"), ("Indu", "इंदु"), ("Jaya", "जया"), ("Kanchan", "कंचन"),
    ("Malti", "मालती"), ("Manorama", "मनोरमा"), ("Shashi", "शशि"), ("Sharda", "शारदा"),
    ("Sunaina", "सुनैना"), ("Uma", "उमा"), ("Vidya", "विद्या"), ("Yashoda", "यशोदा"),
    ("Sarla", "सरला"), ("Chanda", "चंदा"), ("Gayatri", "गायत्री"), ("Hema", "हेमा"),
    ("Bimla", "बिमला"), ("Phoolwati", "फूलवती"), ("Nargis", "नरगिस"), ("Shabnam", "शबनम"),
    ("Rehana", "रेहाना"), ("Farhana", "फ़रहाना"), ("Nazia", "नाज़िया"), ("Sana", "सना"),
    ("Heena", "हीना"), ("Afsana", "अफ़साना"), ("Tabassum", "तबस्सुम"), ("Rubina", "रुबीना"),
    ("Sabiha", "सबीहा"), ("Shaheen", "शाहीन"), ("Yasmin", "यास्मीन"), ("Nazma", "नाज़मा"),
    ("Firdaus", "फ़िरदौस"), ("Parveen", "परवीन"), ("Ishrat", "इशरत"), ("Shagufta", "शगुफ़्ता"),
    ("Simran", "सिमरन"), ("Navneet", "नवनीत"), ("Baljeet", "बलजीत"), ("Amandeep", "अमनदीप"),
    ("Jasleen", "जसलीन"), ("Agnes", "एग्नेस"), ("Teresa", "टेरेसा"), ("Martha", "मार्था"),
]
SURNAMES = [
    ("Saxena", "सक्सेना"), ("Agarwal", "अग्रवाल"), ("Bajpai", "बाजपेयी"), ("Dwivedi", "द्विवेदी"),
    ("Trivedi", "त्रिवेदी"), ("Chaturvedi", "चतुर्वेदी"), ("Shukla", "शुक्ला"), ("Awasthi", "अवस्थी"),
    ("Dixit", "दीक्षित"), ("Tripathi", "त्रिपाठी"), ("Upadhyay", "उपाध्याय"), ("Pathak", "पाठक"),
    ("Dubey", "दुबे"), ("Chaubey", "चौबे"), ("Rastogi", "रस्तोगी"), ("Kashyap", "कश्यप"),
    ("Nigam", "निगम"), ("Bhatnagar", "भटनागर"), ("Mathur", "माथुर"), ("Katiyar", "कटियार"),
    ("Sachan", "सचान"), ("Gangwar", "गंगवार"), ("Rathore", "राठौर"), ("Chandel", "चंदेल"),
    ("Bhadauria", "भदौरिया"), ("Tomar", "तोमर"), ("Sengar", "सेंगर"), ("Baghel", "बघेल"),
    ("Saini", "सैनी"), ("Kanaujia", "कनौजिया"), ("Jaiswal", "जायसवाल"), ("Sonkar", "सोनकर"),
    ("Valmiki", "वाल्मीकि"), ("Gautam", "गौतम"), ("Bharti", "भारती"), ("Diwakar", "दिवाकर"),
    ("Kewat", "केवट"), ("Rajbhar", "राजभर"), ("Chaurasia", "चौरसिया"), ("Vishwakarma", "विश्वकर्मा"),
    ("Soni", "सोनी"), ("Khanna", "खन्ना"), ("Malhotra", "मल्होत्रा"), ("Kapoor", "कपूर"),
    ("Sethi", "सेठी"), ("Bhardwaj", "भारद्वाज"), ("Naqvi", "नक़वी"), ("Zaidi", "ज़ैदी"),
    ("Abbasi", "अब्बासी"), ("Farooqui", "फ़ारूक़ी"), ("Usmani", "उस्मानी"), ("Mirza", "मिर्ज़ा"),
    ("Rehman", "रहमान"), ("Haider", "हैदर"), ("Jafri", "जाफ़री"), ("Mansoori", "मंसूरी"),
    ("Salmani", "सलमानी"), ("Alvi", "अल्वी"), ("Sandhu", "संधू"), ("Dhillon", "ढिल्लों"),
    ("Grewal", "ग्रेवाल"), ("Bajwa", "बाजवा"), ("Sidhu", "सिद्धू"), ("Fernandes", "फ़र्नांडिस"),
    ("Massey", "मैसी"), ("Bisht", "बिष्ट"), ("Negi", "नेगी"), ("Rana", "राणा"),
    ("Solanki", "सोलंकी"), ("Purohit", "पुरोहित"), ("Bhatt", "भट्ट"), ("Tandon", "टंडन"),
    ("Mehrotra", "मेहरोत्रा"), ("Kesarwani", "केसरवानी"), ("Rajak", "रजक"), ("Pandit", "पंडित"),
]
# Canary identities: deliberately rare names (north-east, south, Parsi) that should not
# be in any gazetteer. Latin script only, like the practice canaries.
CANARY_GIVEN = [
    "Lalremruata", "Kezhokhoto", "Ibomcha", "Tombisana", "Wanbor", "Phrangsngi", "Iaibha",
    "Sengkmen", "Yangchen", "Neiphiu", "Vizolie", "Chubatemsu", "Thejavizo", "Lhingneilam",
    "Zothanpuii", "Ilampirai", "Anbuselvi", "Kuzhali", "Ruzbeh", "Nedunchezhiyan",
]
CANARY_SURNAMES = [
    "Hmar", "Thangjam", "Kikon", "Lyngdoh", "Kharkongor", "Rymbai", "Wahlang", "Nongrum",
    "Syiem", "Tariang", "Haokip", "Vaiphei", "Zeliang", "Rengma", "Puthran", "Kotian",
    "Nachimuthu", "Dkhar", "Khiangte", "Pachuau",
]
# Name parts that identify nobody on their own (kept unchanged).
GENERIC_LATIN = {"singh", "kaur", "kumar", "kumari", "devi", "bano", "begum", "khatoon", "khatun",
                 "mohammad", "mohammed", "muhammad", "mohd", "md", "sk"}
GENERIC_DEVA = {"सिंह", "कौर", "कुमार", "कुमारी", "देवी", "बानो", "बेगम", "ख़ातून", "खातून", "मोहम्मद"}
KINSHIP_LATIN = {"ji", "jee", "sahab", "saheb", "bhai", "bhaiya", "bhaiyya", "didi", "behenji", "behen",
                 "babu", "amma", "mama", "mami", "chachu", "chacha", "chachi", "papa", "mummy", "maa",
                 "dada", "dadi", "nana", "nani", "bua", "mausi", "bhabhi", "beta", "beti", "uncle",
                 "aunty", "jija", "sir", "madam", "bibi", "baba"}
KINSHIP_DEVA = {"जी", "साहब", "भाई", "भैया", "दीदी", "बहनजी", "बाबू", "अम्मा", "मामा", "चाचा", "पापा", "माँ"}

# Spelling-variant rules used when one original person has several spellings
# (Shanti / Shanthi). Applied to the new name so the variant relationship survives.
VARIANT_RULES = [
    ("ee", "i"), ("oo", "u"), ("w", "v"), ("v", "w"), ("sh", "s"), ("th", "t"), ("x", "ks"),
    ("ks", "x"), ("ou", "au"), ("au", "ou"), ("q", "k"), ("z", "j"), ("y$", "i"), ("i$", "ee"),
    ("i", "ee"), ("u", "oo"), ("a", "aa"), ("$", "a"), ("a$", ""),
]

# ---------------------------------------------------------------------------
# Labels, headers and JSON keys (alternatives; the choice is seeded).
# ---------------------------------------------------------------------------
LABEL_ALTS = {
    "Patient Name:": ["Pt. Name:", "Name of Patient:", "Patient's Name:"],
    "Name:": ["Pt Name:", "Patient:", "Naam:"],
    "Age/Sex:": ["Age / Gender:", "Age-Sex:"],
    "UHID:": ["MR No.:", "Hosp. Reg. No.:", "CR No.:"],
    "IPD No:": ["Admission No.:", "IP No.:", "Indoor Reg. No.:"],
    "Reg No:": ["Regn. No.:", "OPD No.:", "Card No.:"],
    "Address (attendant):": ["Escort's address:", "Bystander address:"],
    "Address:": ["Residence:", "Addr.:", "Resi. Address:"],
    "Mobile:": ["Contact No.:", "Ph. No.:", "Cell:"],
    "Mob:": ["Contact:", "Phone:", "Mob. No.:"],
    "ABHA No:": ["Health ID:", "ABHA ID:"],
    "DOB:": ["D.O.B.:", "Birth Date:", "Date of Birth:"],
    "Consultant:": ["Treating Doctor:", "Under care of:"],
    "Date of Admission:": ["Admitted on:", "DOA:", "Admission Date:"],
    "Date of Discharge:": ["Discharged on:", "DOD:", "Discharge Date:"],
    "Attendant:": ["Escort:", "Accompanied by:", "Bystander:"],
    "Date:": ["Visit Date:", "Dated:"],
    "मरीज़ का नाम:": ["रोगी का नाम:", "मरीज:"],
    "नाम:": ["रोगी का नाम:", "मरीज़:"],
    "पिता का नाम:": ["पिता श्री:", "पिता:"],
    "पति का नाम:": ["पति श्री:", "पति:"],
    "पंजीकरण सं.:": ["रजि. नं.:", "पंजीयन क्रमांक:"],
    "आईपीडी सं.:": ["भर्ती क्रमांक:", "आई.पी. नं.:"],
    "पता:": ["निवास:", "स्थायी पता:"],
    "मोबाइल:": ["फ़ोन:", "संपर्क:", "मो.:"],
    "ग्राम:": ["गाँव:", "मौजा:"],
    "आयु:": ["उम्र:"],
    "भर्ती की तारीख:": ["भर्ती दिनांक:"],
    "छुट्टी की तारीख:": ["डिस्चार्ज दिनांक:", "छुट्टी दिनांक:"],
    "तारीख:": ["दिनांक:"],
}
INLINE_LABELS = [
    (re.compile(r"(, )(Mob\.)(?= )"), ["Ph.", "Cell", "Contact"]),
    (re.compile(r"(?<![A-Za-z])()(Attendant)(?= \()"), ["Escort", "Bystander", "Relative"]),
]
CSV_HEADER_ALTS = {
    "UHID": ["Hospital No", "MR No", "UHID No."],
    "Patient Name": ["Patient's Name", "Name of Patient", "Pt Name"],
    "Gender": ["Sex", "M/F"],
    "Age": ["Age (Yrs)", "Age in Years"],
    "DOB": ["Date of Birth", "Birth Date", "D.O.B"],
    "Relation": ["Rel.", "Relationship"],
    "Relative Name": ["Guardian Name", "Father/Husband Name", "Kin Name"],
    "Address": ["Full Address", "Residential Address", "Addr"],
    "Village/Mohalla": ["Gram/Mohalla", "Village-Locality", "Gaon/Mohalla"],
    "Tehsil": ["Tahsil", "Block"],
    "District": ["Distt", "Zila", "Dist."],
    "PIN": ["Pincode", "Postal Code", "PIN Code"],
    "Mobile": ["Contact#", "Phone No", "Cell No"],
    "Aadhaar No": ["UID No", "Aadhar Number", "UIDAI No"],
    "ABHA No": ["Health ID", "ABHA ID", "PHR ID"],
    "Reg Date": ["Registered On", "Date of Registration", "Regn Dt"],
    "Reg No": ["Panjikaran No", "Regn No", "Reg. Sankhya"],
    "Naam": ["Rogi ka Naam", "Mariz ka Naam", "Poora Naam"],
    "Ling": ["Linga", "Gender"],
    "Umar": ["Aayu", "Umr"],
    "Janm Tithi": ["Janam Tithi", "Janm Dinank"],
    "Pita/Pati ka Naam": ["Abhibhavak ka Naam", "Pita/Pati", "Sambandhi ka Naam"],
    "Pata": ["Poora Pata", "Nivas"],
    "Gaon": ["Gram", "Mauza"],
    "Jila": ["Janpad", "Zila"],
    "Pin Code": ["Pincode", "Dak Pin"],
    "Mobile No": ["Sampark No", "Phone", "Mob. No."],
    "Aadhar": ["Aadhaar Sankhya", "UID"],
    "Registration Date": ["Panjikaran Tithi", "Darj Tithi"],
    "PatientID": ["MRNo", "Pt_ID", "PatNo"],
    "LastName": ["Surname", "FamilyName", "LName"],
    "FirstName": ["GivenName", "FName", "Forename"],
    "Sex": ["Gender", "MF"],
    "DOB (MM/DD/YYYY)": ["BirthDate", "DOB", "Birth Dt (MM/DD/YYYY)"],
    "Guardian": ["NextOfKin", "Care Of", "Guardian Name"],
    "Street": ["AddrLine1", "Address1", "House/Street"],
    "City": ["Town", "Village", "Locality"],
    "Zip": ["PostalCode", "PIN"],
    "Phone": ["Tel", "ContactNo", "Mobile#"],
    "Email": ["E-mail", "EmailID"],
    "Registered (MM/DD/YYYY)": ["RegDate", "Enrolled On", "Registration Dt"],
    "Notes": ["Remarks", "Comments", "Memo"],
    "sample_id": ["specimen_no", "barcode", "accession_no"],
    "patient_name": ["pt_name", "name_of_patient", "patient"],
    "age_sex": ["age_gender", "age/sex", "agesex"],
    "uhid": ["hospital_no", "mr_no", "reg_no"],
    "ref_doctor": ["referring_physician", "ref_by", "consultant"],
    "test": ["investigation", "test_name", "parameter"],
    "result": ["observed_value", "value", "finding"],
    "unit": ["units", "uom"],
    "ref_range": ["bio_ref_interval", "normal_range", "reference"],
    "collected_on": ["sample_date", "collection_dt", "drawn_on"],
    "reported_on": ["report_date", "reported_dt", "released_on"],
    "bill_no": ["invoice_no", "bill_number", "receipt_no"],
    "pmjay_id": ["ab_pmjay_card", "pmjay_no", "ayushman_id"],
    "payer_pan": ["pan_no", "pan", "payer_pan_no"],
    "policy_no": ["policy_number", "insurance_policy", "pol_no"],
    "package_code": ["hbp_code", "pkg_code", "package"],
    "procedure": ["procedure_name", "surgery", "treatment"],
    "admission_date": ["doa", "admitted_on", "date_of_admission"],
    "discharge_date": ["dod", "discharged_on", "date_of_discharge"],
    "amount_inr": ["claim_amount", "amount_rs", "bill_amount"],
    "status": ["claim_status", "state", "stage"],
    "remarks": ["comments", "note", "details"],
}
JSON_KEY_ALTS = {
    "mobile": ["contact_no", "phone_no", "cell"],
    "patient_ref": ["pt_uhid", "patient_id", "mrn"],
    "uhid": ["hospital_no", "mr_no", "reg_no"],
    "hospital_uhid": ["hosp_reg_no", "hospital_id", "uhid_no"],
    "phone": ["contact_number", "mobile_no", "tel"],
    "patient_name": ["pt_name", "full_name", "name_of_patient"],
    "age_sex": ["age_gender", "agesex", "age_and_sex"],
    "source_path": ["export_file", "src", "file_path"],
    "visit_date": ["seen_on", "opd_date", "date_of_visit"],
    "doctor": ["consultant", "attending", "seen_by"],
    "address_note": ["addr_remarks", "address_text", "residence_note"],
    "reviewed_by": ["checked_by", "verified_by"],
    "first": ["given_name", "fname", "first_name"],
    "last": ["family_name", "lname", "surname"],
    "local": ["name_local", "name_hi", "vernacular"],
    "dob": ["birth_date", "date_of_birth", "dob_iso"],
    "aadhar_no": ["uid_no", "aadhaar", "uidai"],
    "pin": ["pincode", "postal_code", "zip"],
    "village": ["gram", "locality", "gaon"],
    "registered_on": ["reg_date", "enrolled_on", "registration_date"],
    "callback": ["callback_no", "contact", "call_back_number"],
    "raised_by": ["reported_by", "requester", "caller"],
    "referred_by": ["ref_by", "referring_doctor", "ordered_by"],
    "collected": ["collected_at", "sample_time", "collection_ts"],
    "remarks": ["comments", "note", "lab_notes"],
    "notes": ["clinical_notes", "remarks", "obs"],
    "date": ["result_date", "test_date", "dt"],
    "by_uhid": ["index_by_hospital_no", "uhid_index", "by_mrn"],
    "by_name": ["index_by_patient", "name_index", "by_patient"],
    "guardian": ["next_of_kin", "kin", "relative"],
    "contact": ["contact_info", "reach", "telecom"],
    "sex": ["gender", "m_f"],
    "abha": ["abha_no", "health_id"],
}

# ---------------------------------------------------------------------------
# Identifier, phone and date formats.
# ---------------------------------------------------------------------------
ID_RULES = [
    ("snj_uhid", re.compile(r"SNJ([/-])(?P<yy>\d{2})\1(?P<n>\d{6})", re.IGNORECASE),
     ["SMH-20{yy}/{n}", "SMH/{n}/{yy}", "SNJ.{yy}.{n}"]),
    ("jjh_uhid", re.compile(r"JJH-(?P<n>\d{7})", re.IGNORECASE), ["JJCH/{n}", "JJ-CH-{n}", "JJ{n}"]),
    ("ass_uhid", re.compile(r"UHID-(?P<n>\d{6})", re.IGNORECASE), ["ASS.{n}", "ASS/UH/{n}", "AS-{n}"]),
    ("ass_ipd", re.compile(r"ADM(?P<n>\d{6})", re.IGNORECASE), ["IPNO/{n}", "ASS-IP-{n}", "IPD.{n}"]),
    ("snj_ipd", re.compile(r"IPD-(?P<yyyy>\d{4})-(?P<n>\d{5})", re.IGNORECASE), ["ADM/{yy}/{n}", "IPD{yy}-{n}", "SMH-ADM-{n}"]),
    ("jjh_ipd", re.compile(r"IP([/-])(?P<yy>\d{2})\1(?P<n>\d{5})", re.IGNORECASE), ["JJ/IP/20{yy}/{n}", "IPD-JJ-{n}", "JJ.IP.{n}"]),
    ("dhh_uhid", re.compile(r"DHH(?P<yyyy>\d{4})-(?P<n>\d{6})", re.IGNORECASE), ["HRD/{yyyy}/{n}", "DHH.{n}", "DH-HDI-{n}"]),
    ("dhh_ipd", re.compile(r"DHH-IPD-(?P<n>\d{5})", re.IGNORECASE), ["DHH/ADM/{n}", "HDI-IP-{n}", "DHIP{n}"]),
]
PHONE_FMTS = [
    lambda d: f"(+91) {d[:5]}-{d[5:]}",
    lambda d: f"0091 {d[:4]} {d[4:7]} {d[7:]}",
    lambda d: f"+91.{d[:5]}.{d[5:]}",
    lambda d: f"{d[:4]}-{d[4:7]}-{d[7:]}",
    lambda d: f"+91 {d[:3]} {d[3:6]} {d[6:]}",
    lambda d: f"91-{d}",
    lambda d: f"0{d[:5]} {d[5:]}",
    lambda d: f"+91{d}",
]
PHONE_FMTS_DEVA = [
    lambda d: f"{d[:5]} {d[5:]}",
    lambda d: f"+91 {d[:5]}-{d[5:]}",
    lambda d: f"0{d}",
]
PHONE_FMTS_FILENAME = [
    lambda d: f"{d[:5]}-{d[5:]}",
    lambda d: f"91-{d}",
    lambda d: f"0{d}",
    lambda d: f"{d[:4]}-{d[4:7]}-{d[7:]}",
]
ASCII_TO_DEVA = str.maketrans("0123456789", "०१२३४५६७८९")
DEVA_TO_ASCII = str.maketrans("०१२३४५६७८९", "0123456789")
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTH = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
         "October", "November", "December"]
HI_MONTH = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर",
            "नवंबर", "दिसंबर"]
DATE_FMTS_CSV = [
    lambda d: f"{d.day:02d}-{MON[d.month - 1]}-{d.year}",
    lambda d: f"{d.day:02d} {MON[d.month - 1]} {d.year}",
    lambda d: f"{d.day} {MONTH[d.month - 1]} {d.year}",
    lambda d: f"{d.year}/{d.month:02d}/{d.day:02d}",
]
DATE_FMTS_TEXT = DATE_FMTS_CSV + [lambda d: f"{MON[d.month - 1]} {d.day:02d}, {d.year}"]
def DATE_FMT_HINDI(d):
    return f"{d.day} {HI_MONTH[d.month - 1]} {d.year}"


DATE_RX = re.compile(r"(\d{1,2})([/.\-])(\d{1,2})\2(\d{4})")
ISO_DATE_RX = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
DATES_SHARE = 60  # percent of eligible files whose dates are rewritten
JSON_FORMATS = ("json", "fhir")
# one JSON string literal, escapes included (used to edit \uXXXX-escaped values)
JSON_STR_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')
JSON_UESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})")

CANARY_TEMPLATES = {
    "discharge": "Informant: {name} {phone}",
    "nursing": "Consent witnessed by {name}, ph {phone}",
    "csv": "called by {name} {phone}",
    "rx": "Escorted by neighbour {name}, contact {phone}",
}

LATIN_WORD = re.compile(r"[A-Za-z]+")
DEVA_WORD = re.compile(r"[\u0900-\u097F]+")
WORD_RE = re.compile(r"[A-Za-z]+|[\u0900-\u097F]+")
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
DOCTOR_RE = re.compile(r"\b(?:Dr|DR)\.?[ \t]+[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+)?")
DOCTOR_DEVA_RE = re.compile(r"डॉ\.?\s*[\u0900-\u097F]+(?:\s+[\u0900-\u097F]+)?")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def stable_int(*parts) -> int:
    data = "\x1f".join(str(p) for p in parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big")


def pick(options, *parts):
    return options[stable_int(*parts) % len(options)]


def is_deva(s: str) -> bool:
    return any("\u0900" <= c <= "\u097f" for c in s)


def word_char(ch: str) -> bool:
    return ch.isalnum() or unicodedata.category(ch).startswith("M")


def find_all(text: str, needle: str) -> list[tuple[int, int]]:
    """Occurrences of needle that do not start or end inside a word (underscore is a separator)."""
    out = []
    if not needle:
        return out
    left, right = word_char(needle[0]), word_char(needle[-1])
    i = text.find(needle)
    while i >= 0:
        j = i + len(needle)
        if not ((left and i > 0 and word_char(text[i - 1])) or (right and j < len(text) and word_char(text[j]))):
            out.append((i, j))
        i = text.find(needle, i + 1)
    return out


def apply_map(text: str, mapping: dict, mask: bytearray | None = None):
    """Replace every bounded occurrence of each key, longest first, never inside a masked span."""
    cands, blocked = [], Counter()
    for old in mapping:
        for i, j in find_all(text, old):
            if mask is not None and any(mask[i:j]):
                blocked[old] += 1
                continue
            cands.append((i, j, old))
    cands.sort(key=lambda c: (c[0] - c[1], c[0]))
    taken_mask = bytearray(len(text))
    taken = []
    for i, j, old in cands:
        if any(taken_mask[i:j]):
            continue
        taken_mask[i:j] = b"\x01" * (j - i)
        taken.append((i, j, old))
    taken.sort()
    parts, pos, hits = [], 0, Counter()
    for i, j, old in taken:
        parts.append(text[pos:i])
        parts.append(mapping[old])
        pos = j
        hits[old] += 1
    parts.append(text[pos:])
    return "".join(parts), hits, blocked


def b64_blobs(text: str):
    """Base64 runs that decode to printable UTF-8 text (attachments)."""
    for m in B64_RE.finditer(text):
        tok = m.group(0)
        if len(tok) % 4:
            continue
        try:
            dec = base64.b64decode(tok, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec and all(c.isprintable() or c in "\r\n\t" for c in dec):
            yield m.start(), m.end(), dec


def protect_mask(text: str, texts, doctors: bool = True) -> bytearray:
    mask = bytearray(len(text))
    for t in texts:
        for i, j in find_all(text, t):
            mask[i:j] = b"\x01" * (j - i)
    if doctors:
        for rx in (DOCTOR_RE, DOCTOR_DEVA_RE):
            for m in rx.finditer(text):
                mask[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    return mask


def apply_case(orig: str, new: str) -> str:
    if orig.isupper() and len(orig) > 1:
        return new.upper()
    if orig[:1].isupper():
        return new[:1].upper() + new[1:].lower()
    return new.lower()


def ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def similar(a: str, b: str) -> bool:
    r = ratio(a, b)
    return r >= 0.8 or (r >= 0.6 and a[:1] == b[:1])


def is_generic(tok: str) -> bool:
    if is_deva(tok):
        return tok in GENERIC_DEVA or tok in KINSHIP_DEVA
    return tok.lower() in GENERIC_LATIN or tok.lower() in KINSHIP_LATIN


def decode_lenient(raw: bytes, enc: str | None) -> str:
    try:
        return raw.decode(enc or "utf-8")
    except (UnicodeError, LookupError):
        return raw.decode("utf-8", errors="replace")


def csv_shape(text: str, delim: str):
    try:
        return [len(r) for r in csv.reader(io.StringIO(text, newline=""), delimiter=delim)]
    except csv.Error:
        return None


def json_literal_like(old_lit: str, value: str) -> str:
    """Encode value as a JSON string literal in the style of old_lit: \\uXXXX escapes for
    non-ASCII text when old_lit used them (with the same hex case), raw UTF-8 otherwise."""
    escapes = JSON_UESC_RE.findall(old_lit)
    lit = json.dumps(value, ensure_ascii=bool(escapes))
    if escapes and any(c in "ABCDEF" for e in escapes for c in e):
        lit = JSON_UESC_RE.sub(lambda m: "\\u" + m.group(1).upper(), lit)
    return lit


def escaped_json_strings(text: str):
    """(start, end, decoded) for every JSON string literal that uses \\uXXXX escapes."""
    for m in JSON_STR_RE.finditer(text):
        lit = m.group(0)
        if "\\u" not in lit:
            continue
        try:
            val = json.loads(lit)
        except ValueError:
            continue
        if isinstance(val, str):
            yield m.start(), m.end(), val


def map_escaped_json(text: str, fn):
    """Apply fn to the decoded value of every escaped JSON string literal and re-encode
    the changed ones in their original style. Returns (text, literals changed)."""
    parts, pos, n = [], 0, 0
    for s, e, val in list(escaped_json_strings(text)):
        new = fn(val)
        if new != val:
            parts.append(text[pos:s])
            parts.append(json_literal_like(text[s:e], new))
            pos = e
            n += 1
    parts.append(text[pos:])
    return "".join(parts), n


def decoded_json_text(text: str) -> str:
    """Decoded escaped string values, so truth checks see "\\u0915..." as the letters."""
    return "\n".join(v for _, _, v in escaped_json_strings(text))


def practice_vocabulary(kit: Path, truth: dict) -> set[str]:
    """Every Latin (lower-cased) and Devanagari word in the practice inputs, attacker files and truth."""
    vocab: set[str] = set()

    def add(s: str) -> None:
        vocab.update(w.lower() for w in LATIN_WORD.findall(s))
        vocab.update(DEVA_WORD.findall(s))

    inp = kit / "dev" / "input"
    encs = {rel: f.get("encoding") for rel, f in truth["files"].items()}
    for p in sorted(inp.rglob("*")):
        if p.is_file():
            rel = p.relative_to(inp).as_posix()
            s = decode_lenient(p.read_bytes(), encs.get(rel))
            add(rel)
            add(s)
            for _, _, dec in b64_blobs(s):
                add(dec)
    att = kit / "dev" / "attacker"
    if att.is_dir():
        for p in sorted(att.glob("*")):
            if p.is_file():
                add(p.read_bytes().decode("utf-8", errors="replace"))
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                add(e["surface"])
                for t in e.get("tokens") or []:
                    add(t)
    return vocab


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
class CanaryPool:
    def __init__(self, seed: int, vocab: set[str], reserved: set[str]):
        def clean(names):
            out = [n for n in dict.fromkeys(names) if n.lower() not in vocab and n.lower() not in reserved]
            random.Random(stable_int(seed, "canary-pool", len(out))).shuffle(out)
            return out

        self.given = clean(CANARY_GIVEN)
        self.surnames = clean(CANARY_SURNAMES)

    def take(self, role: str) -> str:
        pool = self.surnames if role == "s" else self.given
        if not pool:
            raise SystemExit("chaos_gen: canary name pool exhausted")
        return pool.pop(0)


class NameMapper:
    """One global token map: every original name token gets one new token (per script)."""

    def __init__(self, truth: dict, seed: int, vocab: set[str], canaries: CanaryPool):
        self.seed = seed
        self.vocab = vocab
        self.latin: dict[str, str] = {}
        self.deva: dict[str, str] = {}
        self.canary: dict[str, str] = {}
        self.used: set[str] = set()
        self.info = Counter()
        self.groups: list[tuple[str, list[str], list[str]]] = []
        self.pools = self._pools()
        self._build(truth, canaries)

    def _pools(self):
        pools = {}
        for key, table in (("m", GIVEN_MALE), ("f", GIVEN_FEMALE), ("s", SURNAMES)):
            items, seen = [], set()
            for lat, dev in table:
                low = lat.lower()
                if low in seen:
                    continue
                seen.add(low)
                if low not in self.vocab and dev not in self.vocab:
                    items.append((low, dev))
            self.info[f"table_{key}"] = len(seen)
            self.info[f"usable_{key}"] = len(items)
            random.Random(stable_int(self.seed, "pool", key)).shuffle(items)
            pools[key] = items
        return pools

    def _take(self, kind: str):
        order = {"m": "mfs", "f": "fms", "s": "s"}[kind]
        for k in order:
            pool = self.pools[k]
            while pool:
                lat, dev = pool.pop(0)
                if lat not in self.used:
                    self.used.add(lat)
                    return lat, dev
        raise SystemExit(f"chaos_gen: name table exhausted for kind {kind!r}")

    def _variants(self, base: str, n: int) -> list[str]:
        out = []
        for pat, rep in VARIANT_RULES:
            if len(out) == n:
                break
            cand = None
            if pat == "$":
                if base[-1] not in "aeiou":
                    cand = base + rep
            elif pat.endswith("$"):
                core = pat[:-1]
                if base.endswith(core):
                    cand = base[: len(base) - len(core)] + rep
            else:
                i = base.find(pat, 1)
                if i >= 0:
                    cand = base[:i] + rep + base[i + len(pat):]
            if cand and cand != base and len(cand) >= 3 and cand not in self.used and cand not in self.vocab:
                out.append(cand)
                self.used.add(cand)
        k = 1
        while len(out) < n:
            cand = base + base[-1] * k
            k += 1
            if cand not in self.used and cand not in self.vocab:
                out.append(cand)
                self.used.add(cand)
        return out

    def _build(self, truth: dict, canaries: CanaryPool) -> None:
        freq, sur_votes, giv_votes = Counter(), Counter(), Counter()
        gender_votes = defaultdict(Counter)
        lat_lists = defaultdict(lambda: defaultdict(Counter))  # person -> type -> Counter(tuple)
        dev_lists = defaultdict(lambda: defaultdict(Counter))
        canary_roles: dict[str, str] = {}
        for f in truth["files"].values():
            for u in f["units"].values():
                g = next((x.get("true") for x in u.get("fields") or [] if x.get("kind") == "gender"), None)
                for e in u["entities"]:
                    if e["type"] not in NAME_TYPES and e["type"] != "CANARY":
                        continue
                    toks = [t for t in (e.get("tokens") or []) if t and not is_generic(t)]
                    if not toks:
                        continue
                    if e["type"] == "CANARY":
                        for i, t in enumerate(toks):
                            canary_roles.setdefault(t.lower(), "s" if len(toks) > 1 and i == len(toks) - 1 else "g")
                        continue
                    if not any(is_deva(t) for t in toks):
                        tl = tuple(t.lower() for t in toks)
                        freq.update(tl)
                        if len(tl) > 1:
                            sur_votes[tl[-1]] += 1
                            giv_votes.update(tl[:-1])
                        if e["type"] == "PATIENT_NAME" and g in ("M", "F"):
                            gender_votes[tl[0]][g] += 1
                        lat_lists[e["person"]][e["type"]][tl] += 1
                    elif all(is_deva(t) for t in toks):
                        dev_lists[e["person"]][e["type"]][tuple(toks)] += 1

        # spelling variants of one patient's name tokens (same person, same position)
        parent = {t: t for t in freq}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        for person in sorted(lat_lists):
            lists = sorted(lat_lists[person].get("PATIENT_NAME", {}))
            for a, b in itertools.combinations(lists, 2):
                if len(a) == len(b):
                    for x, y in zip(a, b):
                        if x != y and similar(x, y):
                            union(x, y)
                elif min(len(a), len(b)) == 1:
                    single, other = (a, b) if len(a) == 1 else (b, a)
                    x = single[0]
                    best = max(other, key=lambda y: (ratio(x, y), y))
                    if best != x and ratio(x, best) >= 0.75 and similar(x, best):
                        union(x, best)

        members_of = defaultdict(list)
        for t in freq:
            members_of[find(t)].append(t)
        group_dev = {}
        for root in sorted(members_of):
            members = sorted(members_of[root], key=lambda t: (-freq[t], t))
            sv = sum(sur_votes[t] for t in members)
            gv = sum(giv_votes[t] for t in members)
            if sv > gv:
                kind = "s"
            else:
                gvotes = Counter()
                for t in members:
                    gvotes.update(gender_votes[t])
                if gvotes:
                    kind = "f" if gvotes["F"] > gvotes["M"] else "m"
                else:
                    kind = "f" if members[0].endswith(("a", "een")) else "m"
            lat, dev = self._take(kind)
            variants = self._variants(lat, len(members) - 1)
            self.latin[members[0]] = lat
            for old, new in zip(members[1:], variants):
                self.latin[old] = new
            group_dev[root] = dev
            self.info[f"groups_{kind}"] += 1
            if len(members) > 1:
                self.info["variant_groups"] += 1
                self.groups.append((kind, members, [lat] + variants))

        # Devanagari tokens follow the Latin spelling of the same person at the same position
        dvotes = defaultdict(Counter)
        dpos = defaultdict(Counter)
        for person in sorted(dev_lists):
            for typ, dl_counter in sorted(dev_lists[person].items()):
                lat_counter = lat_lists.get(person, {}).get(typ, Counter())
                for dl, n in sorted(dl_counter.items()):
                    for i, d in enumerate(dl):
                        dpos[d]["s" if len(dl) > 1 and i == len(dl) - 1 else "g"] += n
                    cands = sorted(((c, ll) for ll, c in lat_counter.items() if len(ll) == len(dl)),
                                   key=lambda x: (-x[0], x[1]))
                    if not cands:
                        continue
                    if typ == "RELATIVE_NAME" and len(cands) > 1 and cands[0][0] == cands[1][0]:
                        continue
                    for d, low in zip(dl, cands[0][1]):
                        dvotes[d][low] += n
        for d in sorted(set(dpos) | set(dvotes)):
            if dvotes.get(d):
                low = min(dvotes[d].items(), key=lambda x: (-x[1], x[0]))[0]
                root = find(low) if low in parent else None
                if root in group_dev:
                    self.deva[d] = group_dev[root]
                    self.info["deva_aligned"] += 1
                    continue
            kind = "s" if dpos[d]["s"] > dpos[d]["g"] else ("f" if d.endswith("ा") else "m")
            _, dev = self._take(kind)
            self.deva[d] = dev
            self.info["deva_unaligned"] += 1

        for t in sorted(canary_roles):
            self.canary[t] = canaries.take(canary_roles[t]).lower()

    def map_token(self, tok: str, canary: bool = False) -> str:
        if is_deva(tok):
            return tok if canary else self.deva.get(tok, tok)
        table = self.canary if canary else self.latin
        return table.get(tok.lower(), tok)

    def map_surface(self, surface: str, canary: bool = False) -> str:
        def rep(m):
            w = m.group(0)
            if is_deva(w):
                return w if canary else self.deva.get(w, w)
            new = (self.canary if canary else self.latin).get(w.lower())
            return apply_case(w, new) if new else w

        return WORD_RE.sub(rep, surface)

    def map_email(self, s: str) -> str:
        local, at, dom = s.partition("@")
        new_local = LATIN_WORD.sub(lambda m: apply_case(m.group(0), self.latin.get(m.group(0).lower(), m.group(0))), local)
        return new_local + at + dom


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
class Generator:
    def __init__(self, kit: Path, truth: dict, seed: int, variants: set[str]):
        self.kit = kit
        self.truth = truth
        self.seed = seed
        self.V = variants
        self.vocab = practice_vocabulary(kit, truth)
        table_names = {lat.lower() for lat, _ in GIVEN_MALE + GIVEN_FEMALE + SURNAMES}
        self.canary_pool = CanaryPool(seed, self.vocab, table_names)
        self.names = NameMapper(truth, seed, self.vocab, self.canary_pool) if "names" in variants else None
        self.stats = defaultdict(Counter)
        self.practice_digits = self._practice_digits()
        # canonical new form of every MRN that was rewritten in at least one file
        self.ids_replaced: set[str] = set()

    # -- per-surface transforms ------------------------------------------------
    def new_id(self, s: str, filename: bool) -> str | None:
        for name, rx, alts in ID_RULES:
            m = rx.fullmatch(s)
            if not m:
                continue
            g = m.groupdict()
            vals = {"n": g["n"], "yy": g.get("yy") or (g.get("yyyy") or "")[-2:], "yyyy": g.get("yyyy") or ""}
            new = pick(alts, self.seed, "id", name).format(**vals)
            if filename:
                new = new.replace("/", "-")
            if s.islower():
                new = new.lower()
            return new
        return None

    def new_phone(self, s: str, key: str | None, fkey: str, filename: bool) -> str | None:
        digits = re.sub(r"\D", "", s.translate(DEVA_TO_ASCII))
        k = key if key and len(key) == 10 and key.isdigit() else digits[-10:]
        if len(k) != 10 or not digits.endswith(k):
            return None
        deva = any("\u0966" <= c <= "\u096f" for c in s)
        fmts = PHONE_FMTS_FILENAME if filename else (PHONE_FMTS_DEVA if deva else PHONE_FMTS)
        start = stable_int(self.seed, "phone", fkey, s)
        for i in range(len(fmts)):
            new = fmts[(start + i) % len(fmts)](k)
            if deva:
                new = new.translate(ASCII_TO_DEVA)
            if new != s:
                return new
        return None

    def date_format(self, f: dict, fkey: str):
        if f.get("format") in ("csv", "tsv") + JSON_FORMATS:
            fmts = list(DATE_FMTS_CSV)
        else:
            fmts = list(DATE_FMTS_TEXT)
            if any("hindi" in (u.get("tags") or []) for u in f["units"].values()):
                fmts.append(DATE_FMT_HINDI)
        return pick(fmts, self.seed, "datefmt", fkey)

    def new_date(self, s: str, f: dict, fkey: str, known: set[str]) -> str | None:
        """New spelling of a known date: D/M/Y, M/D/Y (by date_hint) or ISO YYYY-MM-DD.

        ISO dates in JSON and FHIR stay ISO (FHIR birthDate and most JSON exports must be
        ISO); everywhere else the date moves to this file's seeded format."""
        if not known:
            return None
        m = ISO_DATE_RX.fullmatch(s)
        if m:
            if f.get("format") in JSON_FORMATS:
                return None
            try:
                dt = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
            return self.date_format(f, fkey)(dt) if dt.isoformat() in known else None
        m = DATE_RX.fullmatch(s)
        if not m:
            return None
        a, b, y = int(m.group(1)), int(m.group(3)), int(m.group(4))
        order = [(b, a), (a, b)] if f.get("date_hint") == "mdy" else [(a, b), (b, a)]
        for d, mo in order:
            try:
                dt = date(y, mo, d)
            except ValueError:
                continue
            if dt.isoformat() in known:
                return self.date_format(f, fkey)(dt)
        return None

    def dates_selected(self, f: dict, fkey: str) -> bool:
        if f.get("format") not in ("text", "csv", "tsv") + JSON_FORMATS or f.get("category") == "clean":
            return False
        if f.get("expect") != "sanitize":
            return False
        return stable_int(self.seed, "dates", fkey) % 100 < DATES_SHARE

    def new_surface(self, e: dict, f: dict, fkey: str, dates_on: bool, known: set[str]) -> str | None:
        t, s, ch = e["type"], e["surface"], e["channel"]
        if self.names is not None:
            if t in NAME_TYPES:
                return self.names.map_surface(s)
            if t == "CANARY":
                return self.names.map_surface(s, canary=True)
            if t == "EMAIL":
                return self.names.map_email(s)
        if "ids" in self.V and t == "MRN":
            return self.new_id(s, ch == "filename")
        if "phones" in self.V and t == "PHONE":
            return self.new_phone(s, e.get("key"), fkey, ch == "filename")
        if dates_on and t == "DOB" and ch != "filename":
            return self.new_date(s, f, fkey, known)
        return None

    def update_entity(self, e: dict, new: str) -> None:
        e["surface"] = new
        if self.names is not None and e.get("tokens") and e["type"] in NAME_TYPES + ("CANARY",):
            e["tokens"] = [self.names.map_token(t, canary=e["type"] == "CANARY") for t in e["tokens"]]
        if e["type"] == "EMAIL" and e.get("key"):
            e["key"] = new.lower()

    # -- labels / headers ------------------------------------------------------
    def fill_json_name_parts(self, text: str, fc: dict):
        """Map FHIR "given" / "family" values that consist of this file's own name tokens.

        Values are decoded first, so a \\uXXXX-escaped Devanagari name is mapped like a
        plain one, then written back in the literal's own style (escaped or raw UTF-8)."""
        toks = set()
        for u in fc["units"].values():
            for e in u["entities"]:
                if e["type"] in NAME_TYPES:
                    toks.update(t if is_deva(t) else t.lower() for t in e.get("tokens") or [] if not is_generic(t))
        if not toks:
            return text, 0
        n = 0

        def one(val: str) -> str:
            nonlocal n
            if not 1 <= len(val) <= 60 or "\n" in val:
                return val
            words = WORD_RE.findall(val)
            if not words or WORD_RE.sub("", val).strip(" ._-"):
                return val
            keys = [w if is_deva(w) else w.lower() for w in words]
            if not any(k in toks for k in keys) or not all(k in toks or is_generic(k) for k in keys):
                return val
            new = self.names.map_surface(val)
            n += new != val
            return new

        def literal(m):
            lit = m.group(0)
            try:
                val = json.loads(lit)
            except ValueError:
                return lit
            new = one(val) if isinstance(val, str) else val
            return lit if new == val else json_literal_like(lit, new)

        def strings(m):
            return m.group(1) + JSON_STR_RE.sub(literal, m.group(2))

        text = re.sub(r'("family"\s*:\s*)("(?:[^"\\\n]|\\.){1,400}")', strings, text)
        text = re.sub(r'("given"\s*:\s*)(\[[^\]]*\])', strings, text)
        return text, n

    # -- labels / headers ------------------------------------------------------
    def apply_labels(self, text: str, fkey: str, probes: set[str]):
        changes, n = {}, 0
        olds = sorted(LABEL_ALTS, key=len, reverse=True)
        rx = re.compile(r"(^[ \t]*|[ \t]{2,})(" + "|".join(map(re.escape, olds)) + r")(?=[ \t]|$)", re.MULTILINE)
        mask = protect_mask(text, probes, doctors=False)

        def rep(m):
            nonlocal n
            if any(mask[m.start(2):m.end(2)]):
                return m.group(0)
            old = m.group(2)
            new = pick(LABEL_ALTS[old], self.seed, "label", fkey, old)
            changes[old] = new
            n += 1
            return m.group(1) + new

        text = rx.sub(rep, text)
        for irx, alts in INLINE_LABELS:
            mask = protect_mask(text, probes, doctors=False)

            def irep(m, alts=alts, mask=mask):
                nonlocal n
                if any(mask[m.start(2):m.end(2)]):
                    return m.group(0)
                n += 1
                return m.group(1) + pick(alts, self.seed, "ilabel", fkey, m.group(2))

            text = irx.sub(irep, text)
        return text, n, changes

    def rename_csv_header(self, text: str, delim: str):
        nl = text.find("\n")
        line = text if nl < 0 else text[:nl]
        cr = line.endswith("\r")
        core = line[:-1] if cr else line
        if '"' in core or not delim:
            return text, {}
        cols = core.split(delim)
        taken = set(cols)
        hmap, new_cols = {}, []
        for c in cols:
            alts = CSV_HEADER_ALTS.get(c)
            if alts:
                new = pick(alts, self.seed, "hdr", c)
                if new not in taken and delim not in new:
                    hmap[c] = new
                    taken.add(new)
                    new_cols.append(new)
                    continue
            new_cols.append(c)
        if not hmap:
            return text, {}
        return delim.join(new_cols) + ("\r" if cr else "") + text[len(line):], hmap

    def rename_json_keys(self, text: str, fc: dict):
        protected = {seg for loc in fc["units"] if loc.startswith("/") for seg in loc.split("/")
                     if seg and not seg.isdigit()}
        existing = set(re.findall(r'"((?:[^"\\]|\\.)*)"\s*:', text))
        kmap = {}
        for k in sorted(existing):
            alts = JSON_KEY_ALTS.get(k)
            if not alts or k in protected:
                continue
            new = pick(alts, self.seed, "key", k)
            if new in existing or new in kmap.values():
                continue
            kmap[k] = new
        if not kmap:
            return text, {}
        rx = re.compile(r'"(' + "|".join(map(re.escape, sorted(kmap, key=len, reverse=True))) + r')"(\s*):')
        return rx.sub(lambda m: '"' + kmap[m.group(1)] + '"' + m.group(2) + ":", text), kmap

    # -- canaries --------------------------------------------------------------
    def _practice_digits(self) -> str:
        runs = []
        inp = self.kit / "dev" / "input"
        for p in sorted(inp.rglob("*")):
            if p.is_file():
                s = p.read_bytes().decode("utf-8", errors="replace").translate(DEVA_TO_ASCII)
                runs.extend(re.findall(r"\d{4,}", s))
        return "|".join(runs)

    def plan_canaries(self) -> dict[str, dict]:
        if "canaries" not in self.V:
            return {}
        files = self.truth["files"]

        def text_files(prefix):
            return sorted(r for r, f in files.items() if r.startswith(prefix) and f.get("format") == "text"
                          and f.get("expect") == "sanitize" and "doc" in f["units"])

        pools = {
            "discharge": text_files("discharge/"),
            "nursing": text_files("notes/nursing_"),
            "csv": [r for r in ("registration/arogya_legacy_export.csv", "misc/ambulance_log.csv") if r in files][:1],
            "rx": text_files("prescriptions/"),
        }
        existing = [c for c in self.truth.get("canaries") or []]
        next_id = 1 + max([int(c.split("-")[-1]) for c in existing if c.split("-")[-1].isdigit()] or [-1])
        plan, used_digits = {}, set()
        for kind in ("discharge", "nursing", "csv", "rx"):
            if not pools[kind]:
                continue
            rel = pick(pools[kind], self.seed, "canary-file", kind)
            name = f"{self.canary_pool.take('g')} {self.canary_pool.take('s')}"
            rng = random.Random(stable_int(self.seed, "canary-phone", kind))
            while True:
                digits = rng.choice("6789") + "".join(rng.choice("0123456789") for _ in range(9))
                if digits not in self.practice_digits and digits not in used_digits:
                    break
            used_digits.add(digits)
            phone = pick(PHONE_FMTS, self.seed, "canary-fmt", kind)(digits)
            plan[rel] = {"kind": kind, "pid": f"CANARY-{next_id}", "name": name, "digits": digits,
                         "phone": phone, "line": CANARY_TEMPLATES[kind].format(name=name, phone=phone)}
            next_id += 1
        return plan

    def insert_canary(self, text: str, fc: dict, spec: dict, delim: str | None):
        """Returns (new_text, unit_loc) or (text, None) when no place was found."""
        if spec["kind"] == "csv":
            lines = text.split("\n")
            starts, in_q = [], False
            for i, line in enumerate(lines):
                if not in_q:
                    starts.append(i)
                if line.count('"') % 2:
                    in_q = not in_q
            empty, filled = [], []
            for r in range(1, len(starts)):
                i = starts[r]
                single = (r + 1 < len(starts) and starts[r + 1] == i + 1) or (r + 1 == len(starts) and i == len(lines) - 1)
                core = lines[i].rstrip("\r")
                if not (single and core and f"row:{r - 1}" in fc["units"]) or core.endswith('"'):
                    continue
                (empty if core.endswith(delim or ",") else filled).append((r, i))
            cands = empty or filled
            if not cands:
                return text, None
            r, i = pick(cands, self.seed, "canary-row", spec["pid"])
            cr = "\r" if lines[i].endswith("\r") else ""
            core = lines[i].rstrip("\r")
            lines[i] = core + ("" if core.endswith(delim or ",") else "; ") + spec["line"] + cr
            return "\n".join(lines), f"row:{r - 1}"
        lines = text.split("\n")
        cands = [i for i in range(1, len(lines) - 1) if lines[i].strip()]
        if not cands or "doc" not in fc["units"]:
            return text, None
        half = cands[len(cands) // 2:]
        i = pick(half, self.seed, "canary-line", spec["pid"])
        cr = "\r" if lines[i].endswith("\r") else ""
        lines.insert(i + 1, spec["line"] + cr)
        return "\n".join(lines), "doc"

    # -- per file ---------------------------------------------------------------
    def process(self, rel: str, f: dict, raw: bytes, canary: dict | None):
        st = self.stats
        fc = copy.deepcopy(f)
        fkey = f["sha256"]
        fmt, enc = f.get("format"), f.get("encoding") or "utf-8"
        text = None
        if fmt not in ("pdf", "binary") and raw:
            try:
                t0 = raw.decode(enc)
                if t0.encode(enc) == raw:
                    text = t0
            except (UnicodeError, LookupError):
                text = None
        dates_on = "dates" in self.V and text is not None and self.dates_selected(f, fkey)
        # in JSON / FHIR only DOB values are re-spelled (plus their copies in "exclude")
        dob_surfaces = {e["surface"] for u in fc["units"].values() for e in u["entities"] if e["type"] == "DOB"}

        content_map, fname_map, desired, exclude_new = {}, {}, [], {}
        for u in fc["units"].values():
            known = {x["true"] for x in u.get("dates") or [] if x.get("true")}
            known |= {x["true"] for x in u.get("fields") or [] if x.get("kind") == "dob" and x.get("true")}
            known |= {e["key"] for e in u["entities"] if e["type"] == "DOB" and e.get("key")}
            for e in u["entities"]:
                if text is None and e["channel"] != "filename":
                    continue
                new = self.new_surface(e, f, fkey, dates_on, known)
                if new is None or new == e["surface"]:
                    continue
                target = fname_map if e["channel"] == "filename" else content_map
                if target.get(e["surface"], new) != new:
                    st["skipped"][e["type"]] += 1
                    st["notes"]["mapping_conflict"] += 1
                    continue
                target[e["surface"]] = new
                desired.append((e, new))
            if dates_on:
                for s in u.get("exclude") or []:
                    if fmt in JSON_FORMATS and s not in dob_surfaces:
                        continue
                    new = self.new_date(s, f, fkey, known)
                    if new and new != s and content_map.get(s, new) == new:
                        content_map[s] = new
                        exclude_new[s] = new

        new_text = text
        probes = {p["text"] for u in fc["units"].values() for p in u.get("preserve") or [] if p.get("text")}
        # numeric probes ("91", "1-0-1") cannot be hurt by name edits and would block phones and IDs
        text_probes = {p for p in probes if any(c.isalpha() for c in p)}
        file_notes = Counter()
        if text is not None:
            if content_map:
                addr = {e["surface"] for u in fc["units"].values() for e in u["entities"]
                        if e["type"] in ADDRESS_TYPES and e["surface"] not in content_map}
                guard = text_probes | addr
                parts, pos = [], 0
                for s, e_, dec in list(b64_blobs(new_text)):
                    nd, _, _ = apply_map(dec, content_map, protect_mask(dec, guard))
                    if nd != dec:
                        parts.append(new_text[pos:s])
                        parts.append(base64.b64encode(nd.encode("utf-8")).decode("ascii"))
                        pos = e_
                        file_notes["base64_blobs"] += 1
                new_text = "".join(parts) + new_text[pos:]
                mask = protect_mask(new_text, guard)
                for s, e_, _ in b64_blobs(new_text):
                    mask[s:e_] = b"\x01" * (e_ - s)
                new_text, _, _ = apply_map(new_text, content_map, mask)
                if fmt in JSON_FORMATS:
                    # "\u0915\u092e..." literals hide surfaces from the raw-text pass above:
                    # replace on the decoded value and write it back escaped
                    new_text, n = map_escaped_json(
                        new_text, lambda v: apply_map(v, content_map, protect_mask(v, guard))[0])
                    file_notes["json_escaped_strings"] += n

            if self.names is not None and fmt in ("json", "fhir"):
                # Structured name parts ("given": ["Salma"], "family": "Ansari") are not truth
                # surfaces of their own; left alone they would contradict the replaced full name.
                new_text, n = self.fill_json_name_parts(new_text, fc)
                file_notes["json_name_parts"] += n

            if "labels" in self.V and fmt == "text" and f.get("category") != "clean":
                new_text, n, changes = self.apply_labels(new_text, fkey, text_probes)
                file_notes["labels"] += n
                for u in fc["units"].values():
                    for d in u.get("dates") or []:
                        if d.get("anchor") in changes:
                            d["anchor"] = changes[d["anchor"]]

            if "headers" in self.V and f.get("expect") == "sanitize" and f.get("category") != "clean":
                if fmt in ("csv", "tsv"):
                    new_text, hmap = self.rename_csv_header(new_text, f.get("delimiter") or ",")
                    if hmap:
                        file_notes["csv_headers"] += len(hmap)
                        self._rewrite_paths(fc, lambda p: "col:" + hmap.get(p[4:], p[4:]) if p.startswith("col:") else p)
                elif fmt == "json":
                    new_text, kmap = self.rename_json_keys(new_text, fc)
                    if kmap:
                        file_notes["json_keys"] += len(kmap)
                        self._rewrite_paths(fc, lambda p: "/".join(kmap.get(s, s) for s in p.split("/"))
                                            if p.startswith("/") else p)

            if canary is not None:
                new_text, loc = self.insert_canary(new_text, fc, canary, f.get("delimiter"))
                if loc is None:
                    file_notes["canary_failed"] += 1
                else:
                    unit = fc["units"][loc]
                    pid = canary["pid"]
                    unit["entities"].append({
                        "type": "CANARY", "surface": canary["name"], "person": pid, "role": "patient",
                        "script": "latin", "channel": "content", "match": "name",
                        "tokens": [t.lower() for t in canary["name"].split()], "full": True,
                        "critical": True, "canary": True})
                    unit["entities"].append({
                        "type": "PHONE", "surface": canary["phone"], "person": pid, "role": "patient",
                        "script": "latin", "channel": "content", "match": "digits", "key": canary["digits"],
                        "critical": True, "canary": True})
                    file_notes["canary_added"] += 1
                    canary["loc"] = loc

        # file name
        folder, _, base = rel.rpartition("/")
        new_base = apply_map(base, fname_map)[0] if fname_map else base
        new_rel = f"{folder}/{new_base}" if folder else new_base
        if canary is not None and canary.get("loc"):
            canary["file"] = new_rel

        # validation: keep the file parseable exactly as before
        if text is not None and new_text != text:
            reason = None
            if fmt in ("json", "fhir"):
                try:
                    json.loads(text)
                    ok_before = True
                except Exception:  # noqa: BLE001 - deep / truncated JSON is expected here
                    ok_before = False
                if ok_before:
                    try:
                        json.loads(new_text)
                    except ValueError:
                        reason = "json_broken"
            elif fmt in ("csv", "tsv") and csv_shape(text, f.get("delimiter") or ",") != csv_shape(
                    new_text, f.get("delimiter") or ","):
                reason = "csv_shape_changed"
            try:
                data = new_text.encode(enc)
            except UnicodeEncodeError:
                reason = reason or "encode_failed"
            if reason:
                st["notes"][f"reverted_{reason}"] += 1
                if canary is not None:
                    canary.pop("loc", None)
                return rel, raw, copy.deepcopy(f), False
        else:
            data = raw

        # truth updates: only surfaces that really are in the new file
        hay = (new_text or "") + "\n" + "\n".join(dec for _, _, dec in b64_blobs(new_text or ""))
        if fmt in JSON_FORMATS and new_text:
            hay += "\n" + decoded_json_text(new_text)
        for e, new in desired:
            where = new_base if e["channel"] == "filename" else hay
            if new in where:
                if e["type"] == "MRN":
                    canon = self.new_id(e["surface"].upper(), False)
                    if canon:
                        self.ids_replaced.add(canon)
                self.update_entity(e, new)
                st["replaced"][e["type"]] += 1
            else:
                st["skipped"][e["type"]] += 1
        if exclude_new:
            for u in fc["units"].values():
                if u.get("exclude"):
                    u["exclude"] = [exclude_new[s] if s in exclude_new and exclude_new[s] in hay else s
                                    for s in u["exclude"]]
                    st["replaced"]["exclude_date"] += sum(1 for s in u["exclude"] if s in exclude_new.values())

        # consistency: nothing that should survive may disappear
        if text is not None and new_text != text:
            old_hay = text + "\n" + "\n".join(dec for _, _, dec in b64_blobs(text))
            if fmt in JSON_FORMATS:
                old_hay += "\n" + decoded_json_text(text)
            for p in probes:
                if p in old_hay and p not in hay:
                    st["notes"]["preserve_lost"] += 1
                    print(f"  WARN preserve probe lost in {rel}: {p!r}", file=sys.stderr)
            changed_ids = {id(e) for e, _ in desired}
            for u in fc["units"].values():
                for e in u["entities"]:
                    if id(e) in changed_ids or e["channel"] == "filename":
                        continue
                    if e["surface"] in old_hay and e["surface"] not in hay:
                        st["notes"]["entity_lost"] += 1
                        print(f"  WARN entity lost in {rel}: {e['type']} {e['surface']!r}", file=sys.stderr)
        for k, v in file_notes.items():
            st["notes"][k] += v
        if file_notes["labels"]:
            st["notes"]["files_with_labels"] += 1
        if file_notes["csv_headers"] or file_notes["json_keys"]:
            st["notes"]["files_with_headers"] += 1
        if dates_on and exclude_new:
            st["notes"]["files_with_dates"] += 1
        return new_rel, data, fc, data != raw or new_rel != rel

    @staticmethod
    def _rewrite_paths(fc: dict, fn) -> None:
        for u in fc["units"].values():
            for grp in ("preserve", "dates", "fields"):
                for x in u.get(grp) or []:
                    if isinstance(x.get("path"), str):
                        x["path"] = fn(x["path"])
        fc["generalizable"] = [fn(p) if isinstance(p, str) else p for p in fc.get("generalizable") or []]


def parse_variants(s: str | None) -> set[str]:
    if not s:
        return set(ALL_VARIANTS)
    out = {v.strip() for v in s.split(",") if v.strip()}
    bad = out - set(ALL_VARIANTS)
    if bad:
        raise SystemExit(f"chaos_gen: unknown variant(s) {sorted(bad)}; choose from {','.join(ALL_VARIANTS)}")
    return out


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Generate held-out unseen-format variants of the practice data.")
    ap.add_argument("--kit", required=True, help="path to Secret-Wards-ToolKit")
    ap.add_argument("--out", required=True, help="output root; writes <out>/<seed>/input and truth")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--variants", default=None, help=f"comma list from {','.join(ALL_VARIANTS)} (default: all)")
    ap.add_argument("--verbose", action="store_true", help="print the name-variant groups")
    a = ap.parse_args(argv)

    kit = Path(a.kit).resolve()
    src_in = kit / "dev" / "input"
    truth_path = kit / "dev" / "truth" / "truth.json"
    if not src_in.is_dir() or not truth_path.is_file():
        raise SystemExit(f"chaos_gen: {kit} does not look like the toolkit (dev/input, dev/truth/truth.json)")
    variants = parse_variants(a.variants)
    dest = Path(a.out).resolve() / str(a.seed)
    if dest.exists():
        if not (dest / MARKER).is_file():
            raise SystemExit(f"chaos_gen: {dest} exists and was not made by chaos_gen; refusing to overwrite")
        shutil.rmtree(dest)
    out_in = dest / "input"
    out_in.mkdir(parents=True)
    (dest / "truth").mkdir()

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    gen = Generator(kit, truth, a.seed, variants)
    plan = gen.plan_canaries()

    new_truth = {k: v for k, v in truth.items() if k != "files"}
    new_files: dict[str, dict] = {}
    changed = renamed = 0
    for rel, f in truth["files"].items():
        raw = (src_in / rel).read_bytes()
        new_rel, data, fc, did_change = gen.process(rel, f, raw, plan.get(rel))
        if new_rel in new_files:
            raise SystemExit(f"chaos_gen: two files map to {new_rel}")
        dst = out_in / new_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if data is raw and new_rel == rel:
            shutil.copyfile(src_in / rel, dst)
        else:
            dst.write_bytes(data)
        fc["path"] = new_rel
        fc["sha256"] = hashlib.sha256(data).hexdigest()
        fc["size"] = len(data)
        new_files[new_rel] = fc
        changed += did_change
        renamed += new_rel != rel
    # files on disk that the key does not describe are copied as they are (no truth units)
    extra = 0
    for p in sorted(src_in.rglob("*")):
        if p.is_file():
            rel = p.relative_to(src_in).as_posix()
            if rel not in truth["files"]:
                (out_in / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, out_in / rel)
                extra += 1
    if extra:
        print(f"  WARN {extra} input files are not in truth.json; copied byte-for-byte without truth units",
              file=sys.stderr)
    new_truth["files"] = new_files

    uhid_counts = Counter()
    if "ids" in variants:
        # a patient's UHID changes only if that identifier was really rewritten in some
        # file (matched on the canonical new form, so SNJ/26/1 and SNJ-26-1 count as one)
        for p in new_truth.get("patients", {}).values():
            for hosp, ids in (p.get("uhids") or {}).items():
                new_ids = []
                for x in ids:
                    nx = gen.new_id(x, False)
                    if nx and gen.new_id(x.upper(), False) in gen.ids_replaced:
                        new_ids.append(nx)
                        uhid_counts["updated"] += 1
                    else:
                        new_ids.append(x)
                        uhid_counts["kept"] += 1
                p["uhids"][hosp] = new_ids
    added = [s for s in plan.values() if s.get("loc")]
    new_truth["canaries"] = list(truth.get("canaries") or []) + [s["pid"] for s in added]
    new_truth["chaos"] = True
    new_truth["chaos_info"] = {"generator": "medveil tools/chaos_gen.py", "base_seed": truth.get("seed"),
                               "chaos_seed": a.seed, "variants": sorted(variants)}
    (dest / "truth" / "truth.json").write_text(json.dumps(new_truth, ensure_ascii=False), encoding="utf-8")

    st = gen.stats
    meta = {"seed": a.seed, "variants": sorted(variants), "files_total": len(new_files) + extra,
            "files_changed": changed, "files_renamed": renamed, "files_unindexed": extra,
            "uhids": dict(sorted(uhid_counts.items())),
            "replaced": dict(sorted(st["replaced"].items())), "skipped": dict(sorted(st["skipped"].items())),
            "notes": dict(sorted(st["notes"].items())),
            "names": dict(sorted(gen.names.info.items())) if gen.names else {},
            "canaries_added": [{"pid": s["pid"], "file": s.get("file"), "loc": s["loc"], "name": s["name"],
                                "phone": s["phone"]} for s in added]}
    (dest / MARKER).write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"chaos_gen: seed {a.seed}, variants {','.join(v for v in ALL_VARIANTS if v in variants)}")
    print(f"  output: {dest}")
    print(f"  files: {meta['files_total']} total, {changed} changed, {renamed} renamed, "
          f"{meta['files_total'] - changed} copied byte-for-byte ({extra} not in truth.json)")
    if uhid_counts:
        print(f"  patient uhids: {uhid_counts['updated']} updated, {uhid_counts['kept']} kept (not rewritten in any file)")
    print("  surfaces replaced: " + (", ".join(f"{k} {v}" for k, v in meta["replaced"].items()) or "none"))
    print(f"  surfaces skipped ({sum(meta['skipped'].values())}): "
          + (", ".join(f"{k} {v}" for k, v in meta["skipped"].items()) or "none"))
    print("  notes: " + (", ".join(f"{k} {v}" for k, v in meta["notes"].items()) or "none"))
    if gen.names:
        print("  names: " + ", ".join(f"{k} {v}" for k, v in meta["names"].items()))
        if a.verbose:
            for kind, olds, news in gen.names.groups:
                print(f"    variant group [{kind}] {'/'.join(olds)} -> {'/'.join(news)}")
    for c in meta["canaries_added"]:
        print(f"  canary {c['pid']}: {c['file']} {c['loc']} -> {c['name']} / {c['phone']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
