import json
import os
import random
import re
import smtplib
import uuid
import os
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "replace-this-with-a-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
app.config["OTP_EXPIRY_MINUTES"] = 5
app.config["ALLOWED_IMAGE_EXTENSIONS"] = {"png", "jpg", "jpeg", "webp"}
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))

app.config["MAIL_USE_TLS"] = (
    os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
)

app.config["MAIL_SENDER"] = os.environ.get("MAIL_SENDER")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")

app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_SENDER")

db = SQLAlchemy(app)


def utc_now():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Resume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(250), nullable=False)

    education = db.Column(db.Text, nullable=False)
    experience = db.Column(db.Text, nullable=False)
    projects = db.Column(db.Text, nullable=True)
    skills = db.Column(db.Text, nullable=False)
    languages = db.Column(db.Text, nullable=False)
    certifications = db.Column(db.Text, nullable=True)
    achievements = db.Column(db.Text, nullable=True)
    interests = db.Column(db.Text, nullable=True)

    linkedin = db.Column(db.String(250), nullable=True)
    github = db.Column(db.String(250), nullable=True)
    website = db.Column(db.String(250), nullable=True)
    portfolio = db.Column(db.String(250), nullable=True)

    photo_filename = db.Column(db.String(250), nullable=True)
    theme = db.Column(db.String(50), default="midnight-pro")
    accent_color = db.Column(db.String(20), default="#2563eb")
    layout_style = db.Column(db.String(30), default="split")
    font_style = db.Column(db.String(30), default="inter")
    show_photo = db.Column(db.Boolean, default=False)
    show_socials = db.Column(db.Boolean, default=True)
    show_metrics = db.Column(db.Boolean, default=False)

    slug = db.Column(db.String(120), unique=True, nullable=False, default=lambda: uuid.uuid4().hex[:12])
    completion_score = db.Column(db.Integer, default=0)
    template_name = db.Column(db.String(50), default="executive")
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    user = db.relationship("User", backref=db.backref("resumes", lazy=True))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    input_str = db.Column(db.String(250), nullable=False)
    result = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=utc_now)

    user = db.relationship("User", backref=db.backref("logs", lazy=True))


THEME_OPTIONS = {
    "midnight-pro": {"label": "Midnight Pro", "accent": "#2563eb"},
    "emerald-edge": {"label": "Emerald Edge", "accent": "#059669"},
    "royal-violet": {"label": "Royal Violet", "accent": "#7c3aed"},
    "sunset-copper": {"label": "Sunset Copper", "accent": "#ea580c"},
}

LAYOUT_OPTIONS = {"split", "stacked", "magazine"}
FONT_OPTIONS = {"inter", "poppins", "lora", "manrope"}


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


def is_password_strong(password: str) -> bool:
    if len(password) < 8:
        return False
    return (
        any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


def allowed_image(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_IMAGE_EXTENSIONS"]


def is_valid_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    return url if parsed.netloc else ""


def normalize_phone(phone: str) -> str:
    return re.sub(r"[^\d+ -]", "", phone or "").strip()


def sanitize_multiline_text(value: str) -> str:
    return "\n".join(line.strip() for line in (value or "").splitlines() if line.strip())


def make_slug(full_name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", (full_name or "").strip().lower()).strip("-")
    base = base[:36] if base else "resume"
    candidate = f"{base}-{uuid.uuid4().hex[:6]}"
    while Resume.query.filter_by(slug=candidate).first():
        candidate = f"{base}-{uuid.uuid4().hex[:6]}"
    return candidate


def calculate_completion_score(data: dict) -> int:
    weighted_fields = {
        "full_name": 8,
        "email": 8,
        "phone": 6,
        "title": 7,
        "summary": 10,
        "address": 5,
        "education": 12,
        "experience": 14,
        "projects": 8,
        "skills": 10,
        "languages": 4,
        "linkedin": 3,
        "github": 3,
        "website": 1,
        "portfolio": 1,
    }
    score = 0
    for field, weight in weighted_fields.items():
        if (data.get(field) or "").strip():
            score += weight
    return min(score, 100)


def build_resume_payload(form, existing_resume: Resume | None = None) -> dict:
    theme = form.get("theme", "midnight-pro").strip()
    accent_color = form.get("accent_color", "").strip() or THEME_OPTIONS.get(theme, {}).get("accent", "#2563eb")
    layout_style = form.get("layout_style", "split").strip()
    font_style = form.get("font_style", "inter").strip()

    if theme not in THEME_OPTIONS:
        theme = "midnight-pro"
    if layout_style not in LAYOUT_OPTIONS:
        layout_style = "split"
    if font_style not in FONT_OPTIONS:
        font_style = "inter"

    payload = {
        "full_name": form.get("full_name", "").strip(),
        "email": form.get("email", "").strip().lower(),
        "phone": normalize_phone(form.get("phone", "")),
        "title": form.get("title", "").strip(),
        "summary": sanitize_multiline_text(form.get("summary", "")),
        "address": form.get("address", "").strip(),
        "education": sanitize_multiline_text(form.get("education", "")),
        "experience": sanitize_multiline_text(form.get("experience", "")),
        "projects": sanitize_multiline_text(form.get("projects", "")),
        "skills": sanitize_multiline_text(form.get("skills", "")),
        "languages": sanitize_multiline_text(form.get("languages", "")),
        "certifications": sanitize_multiline_text(form.get("certifications", "")),
        "achievements": sanitize_multiline_text(form.get("achievements", "")),
        "interests": sanitize_multiline_text(form.get("interests", "")),
        "linkedin": normalize_url(form.get("linkedin", "")),
        "github": normalize_url(form.get("github", "")),
        "website": normalize_url(form.get("website", "")),
        "portfolio": normalize_url(form.get("portfolio", "")),
        "theme": theme,
        "accent_color": accent_color,
        "layout_style": layout_style,
        "font_style": font_style,
        "show_photo": form.get("show_photo") == "on",
        "show_socials": form.get("show_socials") == "on",
        "show_metrics": False,
        "template_name": form.get("template_name", "executive").strip() or "executive",
    }
    payload["completion_score"] = calculate_completion_score(payload)

    if existing_resume and existing_resume.slug:
        payload["slug"] = existing_resume.slug
    else:
        payload["slug"] = make_slug(payload["full_name"])

    return payload

def validate_resume_payload(payload: dict) -> list[str]:
    errors = []
    required_fields = [
        "full_name",
        "email",
        "phone",
        "title",
        "summary",
        "address",
        "education",
        "experience",
        "skills",
        "languages",
    ]

    for field in required_fields:
        if not payload.get(field):
            errors.append(f"{field.replace('_', ' ').title()} is required.")

    if payload.get("email") and not is_valid_email(payload["email"]):
        errors.append("Please enter a valid email address.")

    if payload.get("linkedin") and "linkedin." not in payload["linkedin"]:
        errors.append("LinkedIn URL looks invalid.")

    if payload.get("github") and "github." not in payload["github"]:
        errors.append("GitHub URL looks invalid.")

    if len(payload.get("summary", "")) < 40:
        errors.append("Professional summary should be at least 40 characters.")

    return errors


def save_photo(photo, old_filename: str | None = None) -> str | None:
    if not photo or not photo.filename:
        return old_filename

    if not allowed_image(photo.filename):
        raise ValueError("Profile image must be PNG, JPG, JPEG, or WEBP.")

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    extension = photo.filename.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{extension}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    photo.save(filepath)

    if old_filename:
        old_path = os.path.join(app.config["UPLOAD_FOLDER"], old_filename)
        if os.path.exists(old_path):
            os.remove(old_path)

    return filename


def send_otp_email(recipient_email: str, otp: str) -> tuple[bool, str]:
    sender = app.config["MAIL_SENDER"]
    password = app.config["MAIL_PASSWORD"]

    if not sender or not password:
        print(f"OTP fallback for {recipient_email}: {otp}")
        return False, f"Email not configured. Your OTP is: {otp}"

    msg = EmailMessage()
    msg["Subject"] = "Your Secure Resume Builder OTP"
    msg["From"] = sender
    msg["To"] = recipient_email
    msg.set_content(
        f"Your one-time password is {otp}. It expires in {app.config['OTP_EXPIRY_MINUTES']} minutes."
    )

    try:
        with smtplib.SMTP(
            app.config["MAIL_SERVER"],
            app.config["MAIL_PORT"],
            timeout=10,
        ) as server:
            if app.config["MAIL_USE_TLS"]:
                server.starttls()
            server.login(sender, password)
            server.send_message(msg)
        return True, "OTP sent to your email successfully."
    except Exception as exc:
        print(f"Email send failed for {recipient_email}. OTP: {otp}. Error: {exc}")
        return False, f"Email sending failed. Your OTP is: {otp}"


def require_auth() -> bool:
    return bool(session.get("user_id") and session.get("verified"))


def split_lines(value: str) -> list[str]:
    return [line.strip("•- ").strip() for line in (value or "").splitlines() if line.strip()]


def serialize_resume(resume: Resume) -> dict:
    return {
        "id": resume.id,
        "slug": resume.slug,
        "full_name": resume.full_name,
        "email": resume.email,
        "phone": resume.phone,
        "title": resume.title,
        "summary": resume.summary,
        "address": resume.address,
        "education": split_lines(resume.education),
        "experience": split_lines(resume.experience),
        "projects": split_lines(resume.projects),
        "skills": split_lines(resume.skills),
        "languages": split_lines(resume.languages),
        "certifications": split_lines(resume.certifications),
        "achievements": split_lines(resume.achievements),
        "interests": split_lines(resume.interests),
        "linkedin": resume.linkedin,
        "github": resume.github,
        "website": resume.website,
        "portfolio": resume.portfolio,
        "theme": resume.theme,
        "accent_color": resume.accent_color,
        "layout_style": resume.layout_style,
        "font_style": resume.font_style,
        "show_photo": resume.show_photo,
        "show_socials": resume.show_socials,
        "show_metrics": resume.show_metrics,
        "template_name": resume.template_name,
        "completion_score": resume.completion_score,
        "photo_filename": resume.photo_filename,
        "created_at": resume.created_at.isoformat() if resume.created_at else None,
        "updated_at": resume.updated_at.isoformat() if resume.updated_at else None,
    }


@app.context_processor
def inject_global_theme_data():
    return {
        "THEME_OPTIONS": THEME_OPTIONS,
        "LAYOUT_OPTIONS": sorted(LAYOUT_OPTIONS),
        "FONT_OPTIONS": sorted(FONT_OPTIONS),
    }


@app.route("/")
def index():
      if require_auth():
        return redirect(url_for("dashboard"))
    # return redirect(url_for("login"))
        return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password or not confirm_password:
            flash("All fields are required.", "danger")
        elif not is_valid_email(username):
            flash("Use a valid email address as username.", "danger")
        elif password != confirm_password:
            flash("Passwords do not match.", "danger")
        elif not is_password_strong(password):
            flash(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
                "danger",
            )
        elif User.query.filter_by(username=username).first():
            flash("Account already exists for this email.", "danger")
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            otp = generate_otp()
            session["pending_user_id"] = user.id
            session["pending_email"] = user.username
            session["otp"] = otp
            session["otp_expires_at"] = (
                utc_now() + timedelta(minutes=int(app.config.get("OTP_EXPIRY_MINUTES", 5)))
            ).isoformat()
            session["verified"] = False

            sent, message = send_otp_email(user.username, otp)
            print("OTP STATUS:", sent, message)

            flash(message, "success" if sent else "warning")
            return redirect(url_for("verify_otp"))

        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/resend-otp")
def resend_otp():
    pending_user_id = session.get("pending_user_id")
    pending_email = session.get("pending_email")

    if not pending_user_id or not pending_email:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    otp = generate_otp()
    session["otp"] = otp
    session["otp_expires_at"] = (
        utc_now() + timedelta(minutes=int(app.config.get("OTP_EXPIRY_MINUTES", 5)))
    ).isoformat()

    sent, message = send_otp_email(pending_email, otp)
    flash(message, "success" if sent else "warning")
    return redirect(url_for("verify_otp"))


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    expires_at_str = session.get("otp_expires_at")
    expires_at = datetime.fromisoformat(expires_at_str) if expires_at_str else None

    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()

        if expires_at and utc_now() > expires_at:
            flash("OTP expired. Please request a new code.", "danger")
            return redirect(url_for("resend_otp"))

        if otp_input == session.get("otp"):
            session["user_id"] = session.pop("pending_user_id")
            session["verified"] = True
            session.pop("otp", None)
            session.pop("otp_expires_at", None)
            session.pop("pending_email", None)
            flash("OTP verified successfully.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid OTP. Please try again.", "danger")

    return render_template(
        "verify_otp.html",
        pending_email=session.get("pending_email"),
        expires_at=expires_at,
    )


@app.route("/dashboard")
def dashboard():
    if not require_auth():
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    resumes = Resume.query.filter_by(user_id=user.id).order_by(desc(Resume.updated_at)).all()
    recent_logs = Log.query.filter_by(user_id=user.id).order_by(desc(Log.timestamp)).limit(5).all()

    stats = {
        "total_resumes": len(resumes),
        "avg_completion": int(sum(r.completion_score for r in resumes) / len(resumes)) if resumes else 0,
        "themes_used": len({r.theme for r in resumes}) if resumes else 0,
    }

    return render_template(
        "dashboard.html",
        user=user,
        resumes=resumes,
        recent_logs=recent_logs,
        stats=stats,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/resume/new", methods=["GET", "POST"])
def create_resume():
    if not require_auth():
        return redirect(url_for("login"))

    if request.method == "POST":
        payload = build_resume_payload(request.form)
        errors = validate_resume_payload(payload)

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("resume.html", form_data=request.form, mode="create")

        photo = request.files.get("photo")
        filename = None

        try:
            filename = save_photo(photo)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("resume.html", form_data=request.form, mode="create")

        resume = Resume(
            user_id=session["user_id"],
            photo_filename=filename,
            **payload,
        )
        db.session.add(resume)
        db.session.commit()
        flash("Resume built successfully with a modern professional layout.", "success")
        return redirect(url_for("view_resume", resume_id=resume.id))

    defaults = {
    "theme": "midnight-pro",
    "layout_style": "split",
    "font_style": "inter",
    "template_name": "executive",
    "show_photo": False,
    "show_socials": True,
}
    return render_template("resume.html", form_data=defaults, mode="create")


@app.route("/resume/<int:resume_id>/edit", methods=["GET", "POST"])
def edit_resume(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    resume = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()

    if request.method == "POST":
        payload = build_resume_payload(request.form, existing_resume=resume)
        errors = validate_resume_payload(payload)

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("resume.html", form_data=request.form, resume=resume, mode="edit")

        photo = request.files.get("photo")
        try:
            filename = save_photo(photo, old_filename=resume.photo_filename)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("resume.html", form_data=request.form, resume=resume, mode="edit")

        for key, value in payload.items():
            setattr(resume, key, value)

        if filename:
            resume.photo_filename = filename

        if request.form.get("remove_photo") == "on" and resume.photo_filename:
            old_path = os.path.join(app.config["UPLOAD_FOLDER"], resume.photo_filename)
            if os.path.exists(old_path):
                os.remove(old_path)
            resume.photo_filename = None

        db.session.commit()
        flash("Resume updated successfully.", "success")
        return redirect(url_for("view_resume", resume_id=resume.id))

    return render_template("resume.html", form_data=serialize_resume(resume), resume=resume, mode="edit")


@app.route("/resume/<int:resume_id>")
def view_resume(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    resume = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()
    return render_template("resume_preview.html", resume=resume)


@app.route("/r/<slug>")
def public_resume(slug: str):
    resume = Resume.query.filter_by(slug=slug).first_or_404()
    return render_template("resume_preview.html", resume=resume, public_view=True)


@app.route("/resume/<int:resume_id>/duplicate", methods=["POST"])
def duplicate_resume(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    source = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()

    clone = Resume(
        user_id=source.user_id,
        full_name=source.full_name,
        email=source.email,
        phone=source.phone,
        title=source.title,
        summary=source.summary,
        address=source.address,
        education=source.education,
        experience=source.experience,
        projects=source.projects,
        skills=source.skills,
        languages=source.languages,
        certifications=source.certifications,
        achievements=source.achievements,
        interests=source.interests,
        linkedin=source.linkedin,
        github=source.github,
        website=source.website,
        portfolio=source.portfolio,
        photo_filename=source.photo_filename,
        theme=source.theme,
        accent_color=source.accent_color,
        layout_style=source.layout_style,
        font_style=source.font_style,
        show_photo=source.show_photo,
        show_socials=source.show_socials,
        show_metrics=source.show_metrics,
        template_name=source.template_name,
        completion_score=source.completion_score,
        slug=make_slug(source.full_name),
    )

    db.session.add(clone)
    db.session.commit()
    flash("Resume duplicated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/resume/<int:resume_id>/json")
def resume_json(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    resume = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()
    return jsonify(serialize_resume(resume))


@app.route("/resume/<int:resume_id>/terminal", methods=["GET", "POST"])
def resume_terminal(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    resume = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()
    result = None
    input_str = ""

    if request.method == "POST":
        input_str = request.form.get("input_str", "")
        normalized = "".join(ch.lower() for ch in input_str if ch.isalnum())
        is_palindrome = normalized == normalized[::-1] and normalized != ""
        result = "Palindrome" if is_palindrome else "Not a palindrome"
        db.session.add(Log(user_id=session["user_id"], input_str=input_str, result=result))
        db.session.commit()

    terminal_template = "terminal_basic.html" if len(split_lines(resume.languages)) <= 1 else "terminal_enhanced.html"
    return render_template(
        terminal_template,
        result=result,
        input_str=input_str,
        resume=resume,
    )


@app.route("/resume/<int:resume_id>/delete", methods=["POST"])
def delete_resume(resume_id: int):
    if not require_auth():
        return redirect(url_for("login"))

    resume = Resume.query.filter_by(id=resume_id, user_id=session["user_id"]).first_or_404()

    if resume.photo_filename:
        path = os.path.join(app.config["UPLOAD_FOLDER"], resume.photo_filename)
        if os.path.exists(path):
            os.remove(path)

    db.session.delete(resume)
    db.session.commit()
    flash("Resume deleted.", "info")
    return redirect(url_for("dashboard"))


with app.app_context():
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
