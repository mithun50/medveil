#!/usr/bin/env python3
"""Build the name gazetteers in medveil/lexicon_data/ (dev-time only).

Sources:
  * Faker's en_IN and hi_IN person providers (MIT licence, https://github.com/joke2k/faker)
  * a hand-written list of common North Indian given names and surnames (ours)

Nothing here is taken from the practice dataset. Run: python tools/build_lexicons.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "medveil" / "lexicon_data"

# Our own list of common given names in Uttar Pradesh, Bihar and neighbouring states.
EXTRA_GIVEN = """
Aakash Aarti Abdul Abhay Abhishek Afroz Afsana Ajay Ajit Akbar Akhilesh Alka Altaf Aman Amar Amina
Amit Amrita Anand Anil Anita Anjali Anju Ankit Anoop Anuj Anupam Anuradha Anwar Arjun Arti Arun
Aruna Arvind Asha Ashfaq Ashish Ashok Asif Aslam Ayesha Azhar Babita Babli Babloo Babu Badri Balram
Balwant Banwari Bhagwati Bhagwan Bharat Bhola Bhupendra Bijendra Bimla Bindu Bittu Brij Brijesh
Chandan Chandra Chandrika Champa Chhaya Chhotelal Chinta Danish Deepa Deepak Deepika Devendra
Dharmendra Dhananjay Dilip Dinesh Durga Farha Farhan Farida Faisal Fatima Firoz Ganesh Ganga Gaurav
Geeta Gita Girish Gopal Gori Govind Gudiya Gulshan Gulab Guddi Gyan Hamid Hanif Hari Harish
Harjeet Harpreet Harvinder Hasan Hemant Hira Imran Inder Indu Irfan Ishwar Jagdish Jagjit Jamil
Janaki Jaspreet Javed Jaya Jitendra Jyoti Kailash Kajal Kalpana Kamal Kamla Kamlesh Kanchan Kanta
Karan Kasim Kaushal Kavita Khushboo Kiran Kishan Kishore Krishna Kuldeep Kusum Lakhan Lakshmi Lalit
Lalita Laxmi Madhu Mahendra Mahesh Mamta Manish Manju Manoj Mansoor Maya Meena Meera Mehtab Mohan
Mohini Mohit Mukesh Munni Murli Mushtaq Nadeem Naeem Nafisa Nagendra Nand Narendra Naresh Nargis
Naseem Nasreen Naveen Navneet Neelam Neeraj Neetu Neha Nirmala Nisha Nitin Nitu Noor Pankaj Parvati
Parveen Pawan Phool Pinki Pooja Prabhu Pradeep Prakash Pramod Prashant Pratibha Prem Preeti Priya
Puja Pushpa Rabia Radha Rafiq Raghav Rahul Raj Rajan Rajendra Rajesh Rajeev Rajni Rajkumar Rakesh
Ram Ramesh Rameshwar Rani Ranjana Ranjeet Rashid Rashmi Ravi Reena Rekha Renu Reshma Rinku Rita
Rohit Roshni Ruby Rukhsana Rupa Sabina Sachin Sadhana Sagar Sahil Saira Sajid Sakina Salim Salma
Sameer Sandeep Sangeeta Sanjay Sanjeev Santosh Sapna Sarita Sarla Satish Savita Seema Shabana Shahid
Shakeel Shakti Shalini Shankar Shanti Sharda Shashi Sheela Shilpi Shiv Shivam Shobha Shyam Simran
Sita Sonu Sonia Subhash Sudha Sudhir Sukhwinder Sulochana Suman Sumit Sundar Sunil Sunita Suraj
Suresh Surendra Sushila Sushil Swati Tabassum Tahir Tariq Tarun Uday Umesh Upendra Urmila Usha
Vandana Varun Vijay Vikas Vikram Vimal Vinay Vineeta Vinod Vipin Virendra Vishal Vivek Yashoda
Yogendra Yogesh Zahid Zainab Zakir Zubair Zeenat Farzana Shehnaz Gulnaz Mehrunnisa Rizwan Arshad
Wasim Nasir Iqbal Kaleem Shamim Shamshad Nazia Shaheen Anwari Jameela Hasina Sultana Rehana
Sukhdev Gurpreet Manpreet Baljit Kulwant Paramjit Daljit Amrik Balbir Mary John Joseph Thomas
Anthony Peter Paul Francis Rosy Grace Elizabeth Martha Agnes Jasbir Jaswant Gurmeet Manjeet
""".split()

EXTRA_SURNAMES = """
Yadav Verma Sharma Mishra Tiwari Pandey Shukla Dubey Tripathi Srivastava Saxena Gupta Agarwal
Chauhan Rajput Thakur Singh Kumar Patel Kurmi Maurya Kushwaha Prajapati Nishad Paswan Kori Lodhi
Lodh Rawat Gautam Bharti Jatav Valmiki Rathore Bhadauria Tomar Sengar Baghel Pal Gaderia Kashyap
Sahu Teli Gupta Vaishya Bansal Jaiswal Chaurasia Dwivedi Chaturvedi Bajpai Awasthi Dixit Upadhyay
Ojha Pathak Rai Bhatt Joshi Chaudhary Choudhary Jat Malik Ansari Qureshi Siddiqui Khan Pathan
Shaikh Sheikh Rizvi Zaidi Naqvi Jafri Abbasi Usmani Farooqui Hashmi Mirza Baig Beg Bano Begum
Khatoon Khatun Nisha Fatima Saifi Mansuri Idrisi Rangrez Salmani Alvi Kaur Sandhu Gill Grewal
Bedi Arora Masih Lal Prasad Ram Das Devi Sonkar Dhobi Kanaujia Mallah Bind Rajbhar Chamar
Saroj Kannaujiya Rana Bisht Negi Rawal Mehra Kapoor Khanna Tandon Seth Sinha Jha Thakur Ojha
Gond Kol Kharwar Bhuiyar Nagar Solanki Parihar Chandel Gaur Kalra Bhatia Sethi Wadhwa Narang
""".split()


def main() -> int:
    try:
        from faker.providers.person.en_IN import Provider as EN
        from faker.providers.person.hi_IN import Provider as HI
    except ImportError:
        print("pip install faker first", file=sys.stderr)
        return 1
    given = set(EXTRA_GIVEN)
    given.update(EN.first_names_male)
    given.update(EN.first_names_female)
    given.update(HI.first_names_male)
    given.update(HI.first_names_female)
    surnames = set(EXTRA_SURNAMES)
    surnames.update(EN.last_names)
    surnames.update(HI.last_names)
    clean = lambda xs: sorted({x.strip().replace("\u2019", "'") for x in xs if x.strip() and len(x.strip()) > 1})
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "given_names.txt").write_text("\n".join(clean(given)) + "\n", encoding="utf-8")
    (OUT / "surnames.txt").write_text("\n".join(clean(surnames)) + "\n", encoding="utf-8")
    print(f"given {len(clean(given))}  surnames {len(clean(surnames))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
