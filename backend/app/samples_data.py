SAMPLES = {
    "kyc_sms": {
        "id": "kyc_sms",
        "title": "Fake bank KYC SMS",
        "text": (
            "SBI: Dear Customer, your KYC is PENDING. Your account will be BLOCKED within 24 hours. "
            "Update now: http://sbi-kyc-verify.xyz/login and enter the OTP we just sent."
        ),
    },
    "lookalike": {
        "id": "lookalike",
        "title": "Look-alike payment link",
        "text": (
            "Paytm: Unusual login detected. Secure your wallet immediately. "
            "https://paytm-secure-login.tk/upi/verify?account=wallet "
            "If you ignore this your UPI will be frozen."
        ),
    },
    "digital_arrest": {
        "id": "digital_arrest",
        "title": "Digital-arrest WhatsApp / call script",
        "text": (
            "This is ACP Sharma, Cyber Crime Cell, Lucknow. You are under DIGITAL ARREST for money "
            "laundering linked to your Aadhaar. Do not tell anyone and do not disconnect. "
            "Install AnyDesk immediately and transfer Rs 2,50,000 to court-escrow@oksbi as bail. "
            "A warrant will be issued in 2 hours if you fail."
        ),
    },
}

QUIZ = [
    {
        "id": "q1",
        "question": "Is this SMS a phish?",
        "sample": (
            "HDFC Bank: Your debit card is blocked. Confirm KYC here: "
            "http://hdfc-bank-kyc.top/verify and share the OTP to unblock."
        ),
        "options": [
            "Yes — fake KYC link plus OTP ask",
            "No — banks always send KYC links over SMS",
            "Only if the grammar is poor",
        ],
        "correct_index": 0,
        "is_phish": True,
        "explanation": (
            "HDFC will not use a .top domain or ask for an OTP by SMS. Open the official HDFC app "
            "from your phone, or call the number on the back of your card."
        ),
    },
    {
        "id": "q2",
        "question": "A caller says you are under 'digital arrest' and must install AnyDesk. What should you do?",
        "sample": "Stay on the video call, install AnyDesk, and transfer bail to a UPI ID they dictate.",
        "options": [
            "Comply — it is a court order over video",
            "Hang up, tell a trusted person, and call 1930",
            "Ask them to prove it by telling your Aadhaar number",
        ],
        "correct_index": 1,
        "is_phish": True,
        "explanation": (
            "Digital arrest is a well-known scam. Police do not arrest people over WhatsApp. "
            "Never install remote-access apps for a stranger."
        ),
    },
    {
        "id": "q3",
        "question": "Which part of this address is the real website?",
        "sample": "https://secure-login.paytm.com.help-desk.xyz/upi",
        "options": [
            "paytm.com — because the brand is in the name",
            "help-desk.xyz — the registrable domain on the right",
            "secure-login — because it says secure",
        ],
        "correct_index": 1,
        "is_phish": True,
        "explanation": (
            "Browsers trust the registrable domain just before the path. Here that is help-desk.xyz, "
            "not Paytm. Extra words on the left are decoration."
        ),
    },
    {
        "id": "q4",
        "question": "You get a WhatsApp from 'HR' offering a campus job if you pay a ₹499 registration fee. Phish?",
        "sample": "Congrats! You are selected. Pay ₹499 on this UPI to confirm your internship letter.",
        "options": [
            "Yes — real employers do not charge a joining fee this way",
            "No — small fees are normal for internships",
            "Only a phish if they also ask for OTP",
        ],
        "correct_index": 0,
        "is_phish": True,
        "explanation": (
            "Fake job and scholarship offers target students. Payment of a 'registration fee' over UPI "
            "is the scam. Apply on the company's official careers page."
        ),
    },
    {
        "id": "q5",
        "question": "A friend forwards a QR and says scan it to receive a scholarship refund. Safe?",
        "sample": "Scan this QR, enter UPI PIN to receive ₹12,000 scholarship refund.",
        "options": [
            "Safe if the QR came from a classmate",
            "Unsafe — scanning plus PIN can send money, not receive it",
            "Safe on UPI because UPI is regulated",
        ],
        "correct_index": 1,
        "is_phish": True,
        "explanation": (
            "A QR plus UPI PIN is a payment you make. Refunds never need your PIN. Treat unknown QR "
            "codes like unknown links."
        ),
    },
    {
        "id": "q6",
        "question": "This college notice looks ordinary. Is every official-looking mail safe?",
        "sample": (
            "From: Exam Cell <exams@amity.edu.secure-mail.info>\n"
            "Please download the attached marksheet.exe to view results."
        ),
        "options": [
            "Yes — it names a real university",
            "No — look-alike domain and an .exe attachment",
            "Safe if antivirus is installed",
        ],
        "correct_index": 1,
        "is_phish": True,
        "explanation": (
            "The real domain would end with the university's own name (for example amity.edu), not "
            "secure-mail.info. An .exe 'marksheet' is malware."
        ),
    },
]
