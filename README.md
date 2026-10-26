# ClickCheck

**A small Python toolkit that checks URLs, SMS/WhatsApp text and file hashes for common phishing tricks.**

IBM SkillsBuild National Cybersecurity Bootcamp (5 Oct 2026 – 19 Oct 2026)  
Organised by BharatCares (CSRBOX Group)

| | |
|---|---|
| Student | Rahul |
| College | Guru Nanak Dev University College, Jalandhar |
| Course | BCA 3rd Year |
| Submission files | `clickcheck.py`, `Rahul_ClickCheck.ipynb`, `requirements.txt`, `Rahul_ProjectReport.docx`, `README.md` |

---

## Why I made this

After Masterclass 2 (Think Before You Click) I noticed that almost every scam SMS we get in Punjab follows the same pattern: panic, fake KYC, a weird link, then OTP or UPI. I wanted a tool that a student can run without any paid API.

This is **not** a pentest tool. It never sends exploit payloads. It only reads the text you paste.

## What it does

1. **Password hygiene** – length, mix of characters, common passwords (Masterclass 1)
2. **URL check** – http, IP address, shorteners, look-alike bank/UPI names, odd TLDs (Masterclass 2)
3. **Message check** – urgency, OTP ask, UPI collect, prize, fake courier, job fee (Masterclass 2)
4. **CIA + kill chain** – maps the warnings to Confidentiality / Integrity / Availability and a simple attack path (Masterclass 3)
5. **SHA-256 demo** – hash a file, change one line, hash again (Masterclass 4)

## How to run (Python)

Need Python 3.9+. No extra library for the script.

```
python clickcheck.py
```

Menu:

1. Check a URL  
2. Check a message  
3. Password hygiene  
4. File SHA-256  
5. Run demo + save report  
6. Run tests  
7. Exit  

Without the menu:

```
python clickcheck.py demo
python clickcheck.py test
```

Demo writes `output/clickcheck_report.txt` and `output/clickcheck_report.json`.

## How to run (Notebook)

```
pip install -r requirements.txt
jupyter notebook Rahul_ClickCheck.ipynb
```

Keep `clickcheck.py` in the same folder. In the notebook: Kernel → Restart & Run All.

You can also open the notebook in Google Colab. Upload both `clickcheck.py` and the `.ipynb` file.

## Tests

`python clickcheck.py test` should print **16/16 passed**.

I wrote the tests myself with made-up links like `sbi-kyc-update.xyz`. I did not open any live phishing website.

## Ethical use

- Paste only messages / links that you received, or dummy examples.
- Do not try this on a website you do not own.
- If a real scam already took money, this tool cannot get it back. Use the bank helpline and [cybercrime.gov.in](https://cybercrime.gov.in).

## Files

| File | What it is |
|---|---|
| clickcheck.py | Main program |
| Rahul_ClickCheck.ipynb | Same project in notebook form |
| requirements.txt | Only needed for Jupyter |
| Rahul_ProjectReport.docx | Project report |
| README.md | This file |
| output/ | Created after you run the demo |

## Note

I used IBM Bob once or twice when I was stuck on the URL parser (the missing `http://` thing). The rules, the Punjab examples and the report are my work.
