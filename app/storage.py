import csv
from datetime import datetime
from pathlib import Path
from uuid import uuid4


LOG_FIELDS = [
    "event_id",
    "timestamp",
    "email",
    "password_preview",
    "password_length",
    "status",
    "otp_preview",
    "note",
]


def mask_secret(secret: str) -> str:
    if not secret:
        return "[empty]"
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + ("*" * (len(secret) - 2)) + secret[-1]


def append_demo_event(log_path: Path, email: str, password: str) -> dict[str, str]:
    ensure_log_schema(log_path)
    record = {
        "event_id": uuid4().hex[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "email": email.strip(),
        "password_preview": mask_secret(password.strip()),
        "password_length": str(len(password.strip())),
        "status": "Password captured",
        "otp_preview": "-",
        "note": "Redacted demo record only. No raw password or OTP stored.",
    }

    write_header = not log_path.exists() or log_path.stat().st_size == 0
    with log_path.open("a", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=LOG_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(record)

    return record


def read_demo_events(log_path: Path) -> list[dict[str, str]]:
    if not log_path.exists():
        return []
    ensure_log_schema(log_path)

    with log_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        events: list[dict[str, str]] = []
        changed = False
        for row in reader:
            normalized = normalize_event(row)
            row_changed = normalized.pop("_changed", False)
            changed = changed or row_changed
            events.append(normalized)

        if changed:
            write_demo_events(log_path, events)

        return events


def write_demo_events(log_path: Path, events: list[dict[str, str]]) -> None:
    with log_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=LOG_FIELDS)
        writer.writeheader()
        writer.writerows(events)


def ensure_log_schema(log_path: Path) -> None:
    if not log_path.exists() or log_path.stat().st_size == 0:
        return

    with log_path.open("r", encoding="utf-8", newline="") as file:
        first_line = file.readline().strip()

    expected_header = ",".join(LOG_FIELDS)
    legacy_header = "timestamp,email,password_preview,password_length,note"

    if first_line == expected_header:
        return

    if first_line == legacy_header:
        with log_path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            migrated_events: list[dict[str, str]] = []
            for row in reader:
                migrated_events.append(
                    {
                        "event_id": uuid4().hex[:8],
                        "timestamp": row.get("timestamp", ""),
                        "email": row.get("email", ""),
                        "password_preview": row.get("password_preview", ""),
                        "password_length": row.get("password_length", ""),
                        "status": "Password captured",
                        "otp_preview": "-",
                        "note": row.get("note", "Migrated legacy demo record."),
                    }
                )
        write_demo_events(log_path, migrated_events)


def update_demo_event(log_path: Path, event_id: str, otp_code: str) -> dict[str, str] | None:
    events = read_demo_events(log_path)
    updated_record = None

    for event in events:
        if event["event_id"] == event_id:
            event["status"] = "Blocked by MFA"
            event["otp_preview"] = mask_secret(otp_code.strip())
            event["note"] = "Attacker had the password, but the OTP step blocked account takeover."
            updated_record = event
            break

    if updated_record is not None:
        write_demo_events(log_path, events)

    return updated_record


def normalize_event(row: dict[str, str]) -> dict[str, str]:
    normalized = {
        "event_id": row.get("event_id", ""),
        "timestamp": row.get("timestamp", ""),
        "email": row.get("email", ""),
        "password_preview": row.get("password_preview", row.get("preview", "")),
        "password_length": row.get("password_length", row.get("length", "")),
        "status": row.get("status", "Password captured"),
        "otp_preview": row.get("otp_preview", "-"),
        "note": row.get("note", ""),
    }

    changed = False

    if (
        normalized["timestamp"]
        and not normalized["timestamp"].startswith("20")
        and normalized["email"].startswith("20")
    ):
        normalized = {
            "event_id": normalized["event_id"] or uuid4().hex[:8],
            "timestamp": normalized["email"],
            "email": normalized["password_preview"],
            "password_preview": normalized["password_length"],
            "password_length": normalized["note"],
            "status": normalized["status"] or "Password captured",
            "otp_preview": normalized["otp_preview"] or "-",
            "note": "Recovered malformed legacy demo row.",
        }
        changed = True

    if not normalized["event_id"]:
        normalized["event_id"] = uuid4().hex[:8]
        changed = True

    if not normalized["status"]:
        normalized["status"] = "Password captured"
        changed = True

    if not normalized["otp_preview"]:
        normalized["otp_preview"] = "-"
        changed = True

    normalized["_changed"] = changed
    return normalized
