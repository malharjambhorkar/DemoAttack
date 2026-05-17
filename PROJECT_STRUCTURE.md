# Project Structure

```text
phishing-demo/
├── app.py                  # Flask entrypoint
├── train_model.py          # Model training entrypoint
├── app/
│   ├── __init__.py         # App factory and shared config
│   ├── detector.py         # URL feature extraction and rule checks
│   ├── routes.py           # Flask routes and page flow
│   ├── storage.py          # Demo event logging and CSV migration
│   ├── training.py         # ML training logic
│   ├── static/
│   │   └── style.css
│   └── templates/
│       ├── dashboard.html
│       ├── detector.html
│       ├── index.html
│       ├── mfa.html
│       ├── mfa_result.html
│       ├── result.html
│       └── simulation.html
├── data/
│   ├── demo_events.csv
│   └── phishing_dataset.csv
└── models/
    └── phishing_model.pkl
```
