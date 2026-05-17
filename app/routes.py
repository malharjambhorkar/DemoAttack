from flask import Blueprint, current_app, redirect, render_template, request, url_for
import pandas as pd

from .detector import classify_risk, extract_features, risk_score_from_rules, rule_based_flags
from .storage import append_demo_event, read_demo_events, update_demo_event


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/simulation")
def simulation():
    return render_template("simulation.html")


@main_bp.route("/awareness-login", methods=["POST"])
def awareness_login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    record = append_demo_event(current_app.config["EVENT_LOG_PATH"], email, password)
    return render_template("result.html", record=record)


@main_bp.route("/mfa", methods=["POST"])
def mfa():
    event_id = request.form.get("event_id", "")
    email = request.form.get("email", "")
    return render_template("mfa.html", event_id=event_id, email=email)


@main_bp.route("/mfa-check", methods=["POST"])
def mfa_check():
    event_id = request.form.get("event_id", "")
    otp_code = request.form.get("otp", "")
    record = update_demo_event(current_app.config["EVENT_LOG_PATH"], event_id, otp_code)
    return render_template("mfa_result.html", record=record)


@main_bp.route("/detector", methods=["GET", "POST"])
def detector():
    analysis = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        features = extract_features(url)
        model = current_app.config["MODEL"]
        model_score = None

        if model is not None:
            feature_frame = pd.DataFrame([features], columns=current_app.config["FEATURE_COLUMNS"])
            model_score = float(model.predict_proba(feature_frame)[0][1]) * 100

        rule_analysis = risk_score_from_rules(url)
        rule_score = float(rule_analysis["score"])

        if model_score is not None:
            risk_score = round((rule_score * 0.78) + (model_score * 0.22), 1)
        else:
            risk_score = round(rule_score, 1)

        risk_label, verdict = classify_risk(risk_score)

        analysis = {
            "url": url,
            "prediction": risk_label,
            "verdict": verdict,
            "risk_score": risk_score,
            "rule_score": round(rule_score, 1),
            "model_score": round(model_score, 1) if model_score is not None else None,
            "flags": rule_analysis["flags"],
            "tips": [
                "Check the exact domain, not just the logo or page design.",
                "Avoid login links from email or SMS. Type the known URL manually.",
                "Use MFA so a password alone is not enough.",
            ],
        }

    return render_template("detector.html", analysis=analysis)


@main_bp.route("/demo-log")
def demo_log():
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard")
def dashboard():
    records = list(reversed(read_demo_events(current_app.config["EVENT_LOG_PATH"])))
    total_events = len(records)
    mfa_blocked = sum(record["status"] == "Blocked by MFA" for record in records)
    password_captured = sum(record["status"] == "Password captured" for record in records)
    protected_rate = round((mfa_blocked / total_events) * 100) if total_events else 0

    stats = {
        "total_events": total_events,
        "mfa_blocked": mfa_blocked,
        "password_captured": password_captured,
        "protected_rate": protected_rate,
    }

    return render_template("dashboard.html", records=records[:12], stats=stats)


@main_bp.route("/reset-demo")
def reset_demo():
    log_path = current_app.config["EVENT_LOG_PATH"]
    if log_path.exists():
        log_path.unlink()
    return redirect(url_for("main.demo_log"))
