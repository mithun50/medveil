# Lexicon data

| File | Content | Source |
|---|---|---|
| `given_names.txt` | Indian given names, Latin and Devanagari | Faker `en_IN` and `hi_IN` person providers (MIT licence, joke2k/faker) plus our own list |
| `surnames.txt` | Indian surnames, Latin and Devanagari | same |
| `districts.tsv` | Uttar Pradesh districts, Devanagari names, division | public administrative list (Wikipedia, "Divisions of Uttar Pradesh") |

Regenerate the name files with `python tools/build_lexicons.py`. Nothing in this folder
comes from the practice dataset. The gazetteers only raise or lower confidence; context
rules decide most detections, so unseen names are still caught.
