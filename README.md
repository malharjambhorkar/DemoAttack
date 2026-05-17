# Demo Attack Phishing and Counter Measure

A Flask-based cybersecurity mini project that demonstrates a realistic phishing attack flow and the countermeasures that stop it.

## Educational note

This project is built for classroom awareness and presentation. It does not store raw passwords or OTP values. All evidence shown in the dashboard is intentionally masked.

## What this project includes

- Real-looking phishing entry flow
- Safe credential capture with masked logging only
- MFA checkpoint to block the takeover
- Security dashboard for presentation
- AI-assisted phishing URL detector

## Flow of the project

1. Open the phishing flow page.
2. Enter a sample email and password.
3. Show the captured masked credential preview.
4. Continue to the MFA step.
5. Show that the attacker is blocked at the OTP stage.
6. Open the dashboard to explain the evidence trail.
7. Open the URL detector and test suspicious links.

## Project structure

```text
g:\DEMO ATTACK
|-- app.py
|-- train_model.py
|-- README.md
|-- .gitignore
|-- app/
|   |-- __init__.py
|   |-- routes.py
|   |-- detector.py
|   |-- storage.py
|   |-- training.py
|   |-- templates/
|   `-- static/
|-- data/
|   |-- demo_events.csv
|   `-- phishing_dataset.csv
`-- models/
    `-- phishing_model.pkl
```

## Requirements

- Python 3.11+
- Flask
- pandas
- scikit-learn
- joblib

## Install dependencies

```powershell
pip install flask pandas scikit-learn joblib
```

## Train the model

```powershell
python train_model.py
```

## Run the application

```powershell
python app.py
```

## Open in browser

- `http://127.0.0.1:5000/`
- `http://127.0.0.1:5000/simulation`
- `http://127.0.0.1:5000/dashboard`
- `http://127.0.0.1:5000/detector`

## Presentation flow

1. Start at the home page and explain the four-step attack and defense flow.
2. Open `/simulation` and describe the urgent account verification lure.
3. Submit a test email and password.
4. Show the masked password preview on the captured access page.
5. Move to the MFA step and explain why the attacker fails there.
6. Open `/dashboard` and explain the evidence and blocked attempt.
7. Open `/detector` and test multiple URLs.

## Sample testing URLs

### Low severity

- `https://google.com`
- `https://accounts.google.com`
- `https://github.com/login`

### Medium severity

- `https://portal-student-login.com`
- `https://secure-update-account.net`
- `https://verify-payments-center.com/login`

### High severity

- `http://g00gle-login-alert.xyz`
- `http://micr0soft-account-verify.net`
- `http://banking-update-confirm.info/login`
- `http://instagram-security-check.ru`

### Critical severity

- `http://paypal.com.user-check.ru/login`
- `http://google.com@security-check.xyz`
- `http://bit.ly/verify-your-account`
- `http://secure-login-account-update.free-host.cc`

## What the detector checks

- URL length
- Number of dots
- Number of hyphens
- HTTPS usage
- Digits in the domain
- `@` in the URL
- URL shortener usage
- Suspicious keywords like `login`, `verify`, `secure`, `update`
- Path length

## Files used during demo

- `data/demo_events.csv`
- `data/phishing_dataset.csv`
- `models/phishing_model.pkl`

## Command summary

```powershell
pip install flask pandas scikit-learn joblib
python train_model.py
python app.py
```

## Notes

- Use `python`, not `py`, if your dependencies are installed in the `python` environment.
- Some older root-level files may still exist from previous restructuring, but the active app uses the files inside `data/` and `models/`.
- Folder structure cleanup can be finalized later without affecting the current flow.
