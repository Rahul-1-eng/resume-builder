# ResumeForge — Secure Resume Builder

An upgraded Flask resume builder with a cleaner frontend, Gmail OTP flow, dashboard management, live resume preview, and a modern terminal UI.

## What was improved

- Gmail/email OTP delivery using SMTP configuration
- Modern responsive UI across login, register, dashboard, resume form, and preview pages
- Better resume data model with summary, experience, projects, links, themes, and profile photo
- Instant resume preview after submission
- Dashboard with saved resumes and recent terminal activity
- Print / Save PDF support from the preview page
- Improved palindrome checker that ignores punctuation and spaces in the enhanced mode
- Better validation and safer file uploads
- Flask 3 compatible database initialization

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Gmail OTP setup

For OTP to actually go to Gmail/email, set these environment variables before starting the app:

```bash
export MAIL_SENDER="yourgmail@gmail.com"
export MAIL_PASSWORD="your-gmail-app-password"
export MAIL_SERVER="smtp.gmail.com"
export MAIL_PORT="587"
export MAIL_USE_TLS="true"
export SECRET_KEY="change-this-secret"
```

### Important
Use a **Gmail App Password**, not your normal Gmail password.

If SMTP is not configured, the app falls back to printing the OTP in the server console so development can continue.

## Main routes

- `/register` — create account
- `/login` — login and send OTP
- `/verify_otp` — verify email OTP
- `/dashboard` — view saved resumes and activity
- `/resume/new` — create resume
- `/resume/<id>` — resume preview
- `/resume/<id>/terminal` — open terminal tied to that resume

## Tech stack

- Flask
- Flask-SQLAlchemy
- Bootstrap 5
- Custom CSS
- SQLite

## Notes

- Uploaded profile images are stored in `static/uploads`
- Preview page supports browser print, which can be used to save the resume as PDF
- Default DB is SQLite, but `DATABASE_URL` can be supplied for production
