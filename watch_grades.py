#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
import tomllib

# Base settings.
BASE_URL = "https://school-sotvorchestvo.ru"
AUTH_ENDPOINT = "/api/auth"
AUTH_METHOD = "POST"
AUTH_AS_JSON = True
AUTH_PAYLOAD_TEMPLATE = {
    "login": "{login}",
    "password": "{password}"
}
AUTH_EXTRA_PAYLOAD = {}
AUTH_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": "https://school-sotvorchestvo.ru",
    "referer": "https://school-sotvorchestvo.ru/auth",
}

GRADES_CARD_ENDPOINT = "/api/widget/grades-card"
GRADES_CARD_PARAMS = {}

SEND_COMMENTS = False
SHOW_QUARTER: Optional[Tuple[int, ...]] = None
DEBUG = False

GRADES_CACHE_TTL = 3600  # seconds
DEFAULT_SUBJECT_REMOVE_TOKENS: Tuple[str, ...] = ("яяя",)

DEFAULT_TELEGRAM_ENABLED = True
DEFAULT_TELEGRAM_BOT_TOKEN: Optional[str] = None
DEFAULT_TELEGRAM_CHAT_ID: Optional[str] = None
DEFAULT_TELEGRAM_TIMEOUT = 10

REQUEST_TIMEOUT = 10
DATA_DIR = "cookies"
SETTINGS_FILE = "settings.toml"

# Mapping of grade colors to debt codes (based on grades-card.json sample).
DEBT_COLOR_MAP = {
    "#ff000c": "Незачет",
    "#ff9000": "Не сдал",
}
# Grades that always count as debts when color is missing.
DEBT_GRADE_VALUES = {96}
CONTROL_TEST_DEBT_GRADES = {1, 2}


def debug_info(message: str) -> None:
    if not DEBUG:
        return
    print(f"[DEBUG] {message}", file=sys.stderr)


@dataclass
class DebtItem:
    code: str
    comment: Optional[str]
    text: str


def load_settings() -> Dict[str, Any]:
    try:
        with open(SETTINGS_FILE, "rb") as infile:
            settings = tomllib.load(infile)
    except OSError as exc:
        raise SystemExit(f"Cannot read {SETTINGS_FILE}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Invalid TOML in {SETTINGS_FILE}: {exc}") from exc
    if not isinstance(settings, dict):
        raise SystemExit(f"{SETTINGS_FILE} must contain a TOML table.")
    return settings


def _parse_subject_remove_tokens(settings: Dict[str, Any]) -> Tuple[str, ...]:
    tokens = settings.get("subject_remove_tokens", DEFAULT_SUBJECT_REMOVE_TOKENS)
    if not isinstance(tokens, list):
        return DEFAULT_SUBJECT_REMOVE_TOKENS
    parsed = [item for item in tokens if isinstance(item, str)]
    return tuple(parsed)


def _parse_telegram_settings(settings: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str], int]:
    telegram = settings.get("telegram")
    if not isinstance(telegram, dict):
        return (
            DEFAULT_TELEGRAM_ENABLED,
            DEFAULT_TELEGRAM_BOT_TOKEN,
            DEFAULT_TELEGRAM_CHAT_ID,
            DEFAULT_TELEGRAM_TIMEOUT,
        )
    enabled = telegram.get("enabled", DEFAULT_TELEGRAM_ENABLED)
    bot_token = telegram.get("bot_token", DEFAULT_TELEGRAM_BOT_TOKEN)
    chat_id = telegram.get("chat_id", DEFAULT_TELEGRAM_CHAT_ID)
    timeout = telegram.get("timeout", DEFAULT_TELEGRAM_TIMEOUT)
    if not isinstance(enabled, bool):
        enabled = DEFAULT_TELEGRAM_ENABLED
    if not isinstance(bot_token, str):
        bot_token = None
    if not isinstance(chat_id, str):
        chat_id = None
    if not isinstance(timeout, int):
        timeout = DEFAULT_TELEGRAM_TIMEOUT
    return enabled, bot_token, chat_id, timeout


SETTINGS = load_settings()
SUBJECT_REMOVE_TOKENS = _parse_subject_remove_tokens(SETTINGS)
(
    TELEGRAM_ENABLED,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TELEGRAM_TIMEOUT,
) = _parse_telegram_settings(SETTINGS)


def parse_students() -> List[Dict[str, str]]:
    data = SETTINGS.get("students")
    if not isinstance(data, list):
        raise SystemExit(f"'students' in {SETTINGS_FILE} must be an array of tables.")
    return data


def sanitize_subject_name(subject: str) -> str:
    cleaned = subject
    for token in SUBJECT_REMOVE_TOKENS:
        if not token:
            continue
        pattern = re.compile(re.escape(token), re.IGNORECASE)
        cleaned = pattern.sub("", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def student_identifier(student_name: str, login: Optional[str]) -> str:
    basis = (login or student_name).strip().lower()
    if not basis:
        basis = "student"
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", basis)


def cookie_path(student_name: str, login: Optional[str]) -> str:
    return os.path.join(DATA_DIR, f"{student_identifier(student_name, login)}.json")


def token_path(student_name: str, login: Optional[str]) -> str:
    return os.path.join(DATA_DIR, f"{student_identifier(student_name, login)}.auth.json")


def grades_cache_path(student_name: str, login: Optional[str]) -> str:
    return os.path.join(DATA_DIR, f"{student_identifier(student_name, login)}.grades-card.json")


def notification_path(student_name: str, login: Optional[str]) -> str:
    return os.path.join(DATA_DIR, f"{student_identifier(student_name, login)}.notif.json")


def auth_payload(login: str, password: str) -> Dict[str, str]:
    payload: Dict[str, str] = {}
    for key, template in AUTH_PAYLOAD_TEMPLATE.items():
        payload[key] = template.format(login=login, password=password)
    payload.update(AUTH_EXTRA_PAYLOAD)
    return payload


def apply_access_token(session: requests.Session, token: Optional[str]) -> None:
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.headers.pop("Authorization", None)


def load_tokens(session: requests.Session, path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    access = data.get("accessToken")
    if not isinstance(access, str):
        return None
    apply_access_token(session, access)
    debug_info("Loaded access token from disk")
    return data


def save_tokens(path: str, tokens: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)
    debug_info(f"Saved authentication tokens to {path}")


def load_cached_grades(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    fetched_at = record.get("fetchedAt")
    if not isinstance(fetched_at, str):
        return None
    try:
        fetched_dt = datetime.fromisoformat(fetched_at)
    except ValueError:
        return None
    if fetched_dt.tzinfo is None:
        fetched_dt = fetched_dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if (now - fetched_dt).total_seconds() > GRADES_CACHE_TTL:
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    debug_info(f"Using cached grades from {path}")
    return payload


def save_grades_cache(path: str, data: Dict[str, Any]) -> None:
    record = {
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
        "payload": data,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    debug_info(f"Saved grades cache to {path}")


def load_notification_cache(path: str) -> Optional[Dict[str, str]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    message = data.get("message")
    if not isinstance(message, str):
        return None
    return data


def save_notification_cache(path: str, message: str) -> None:
    record = {
        "sentAt": datetime.now(timezone.utc).isoformat(),
        "message": message,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)


def login(session: requests.Session, login_name: str, password: str) -> Dict[str, Any]:
    url = BASE_URL + AUTH_ENDPOINT
    payload = auth_payload(login_name, password)
    debug_info(f"Authenticating {login_name!r} at {url}")
    if AUTH_HEADERS:
        session.headers.update(AUTH_HEADERS)
    if AUTH_METHOD.upper() == "POST":
        if AUTH_AS_JSON:
            resp = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        else:
            resp = session.post(url, data=payload, timeout=REQUEST_TIMEOUT)
    else:
        resp = session.get(url, params=payload, timeout=REQUEST_TIMEOUT)
    debug_info(f"Auth response: status={resp.status_code}, url={resp.url}")
    if resp.status_code >= 400:
        body = resp.text or "<empty response>"
        snippet = body if len(body) <= 1024 else body[:1024] + "…"
        debug_info(f"Auth response preview: {snippet}")
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        return data
    return {}


def authenticate(session: requests.Session, login_name: str, password: str, token_file: str) -> Dict[str, Any]:
    tokens = login(session, login_name, password)
    access = tokens.get("accessToken") if isinstance(tokens, dict) else None
    apply_access_token(session, access if isinstance(access, str) else None)
    if isinstance(tokens, dict):
        save_tokens(token_file, tokens)
    return tokens


def send_telegram_message(text: str) -> bool:
    if not TELEGRAM_ENABLED:
        return False
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    retries = 3
    delay = 1.0
    for attempt in range(retries):
        try:
            resp = requests.post(url, json=payload, timeout=TELEGRAM_TIMEOUT)
            resp.raise_for_status()
            debug_info("Telegram notification sent")
            return True
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status == 429:
                retry_after = exc.response.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
                debug_info(f"Telegram rate-limited (429), waiting {wait}s")
                time.sleep(wait)
                delay = min(delay * 2, 8.0)
                continue
            debug_info(f"Telegram send failed: {exc}")
            return False
        except requests.RequestException as exc:
            debug_info(f"Telegram send failed: {exc}")
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
    return False


def notify_change(student_name: str, login_name: Optional[str], message: str) -> bool:
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return False
    path = notification_path(student_name, login_name)
    cached = load_notification_cache(path)
    if cached and cached.get("message") == message:
        debug_info("Telegram notification skipped (no change)")
        return False
    if send_telegram_message(message):
        save_notification_cache(path, message)
        return True
    return False


def fetch_grades(session: requests.Session) -> Dict[str, Any]:
    url = BASE_URL + GRADES_CARD_ENDPOINT
    debug_info(f"Fetching grades card: url={url}, params={GRADES_CARD_PARAMS}")
    resp = session.get(url, params=GRADES_CARD_PARAMS, timeout=REQUEST_TIMEOUT)
    debug_info(f"Grades response: status={resp.status_code}, url={resp.url}")
    if resp.status_code >= 400:
        body = resp.text or "<empty response>"
        snippet = body if len(body) <= 1024 else body[:1024] + "…"
        debug_info(f"Response body preview: {snippet}")
        if resp.status_code in (401, 403):
            raise PermissionError(f"Unauthorized HTTP status: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        status_code = data.get("statusCode")
        if status_code in (401, 403):
            raise PermissionError(f"Unauthorized statusCode: {status_code}")
    return data


def normalize_color(color: Optional[str]) -> Optional[str]:
    if not isinstance(color, str):
        return None
    return color.strip().lower()


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def normalize_datetime_for_compare(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def parse_quarter_number(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def quarter_date_range(quarter: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
    start = parse_iso_datetime(quarter.get("dateStart"))
    end = parse_iso_datetime(quarter.get("dateEnd"))
    if start and end:
        return start, end
    week_start: Optional[datetime] = None
    week_end: Optional[datetime] = None
    study_weeks = quarter.get("studyWeeks", [])
    if isinstance(study_weeks, list):
        for week in study_weeks:
            if not isinstance(week, dict):
                continue
            ws = parse_iso_datetime(week.get("dateStart"))
            we = parse_iso_datetime(week.get("dateEnd"))
            if ws:
                week_start = ws if week_start is None else min(week_start, ws)
            if we:
                week_end = we if week_end is None else max(week_end, we)
    return week_start or start, week_end or end


def get_show_quarter_override() -> Optional[Set[int]]:
    if not SHOW_QUARTER:
        return None
    result: Set[int] = set()
    iterable = SHOW_QUARTER if isinstance(SHOW_QUARTER, (list, tuple, set)) else (SHOW_QUARTER,)
    for item in iterable:
        if isinstance(item, int):
            result.add(item)
        elif isinstance(item, str) and item.isdigit():
            result.add(int(item))
    return result or None


def determine_quarter_info(data: Dict[str, Any]) -> Tuple[Set[int], Dict[int, Tuple[Optional[datetime], Optional[datetime]]]]:
    override = get_show_quarter_override()
    response = data.get("response", [])
    if not isinstance(response, list):
        return set(), {}
    quarter_ranges: Dict[int, Tuple[Optional[datetime], Optional[datetime]]] = {}
    available: Set[int] = set()
    active: Set[int] = set()
    now = datetime.now(timezone.utc)
    for entry in response:
        if not isinstance(entry, dict):
            continue
        study_year = entry.get("studyYear", {})
        if not isinstance(study_year, dict):
            continue
        study_quarters = study_year.get("studyQuarters", [])
        if not isinstance(study_quarters, list):
            continue
        for quarter in study_quarters:
            if not isinstance(quarter, dict):
                continue
            q_number = parse_quarter_number(quarter.get("quarterNumber"))
            if q_number is None:
                continue
            start, end = quarter_date_range(quarter)
            quarter_ranges[q_number] = (start, end)
            available.add(q_number)
            if start and end and start <= now <= end:
                active.add(q_number)
    if override:
        debug_info(f"SHOW_QUARTER override active: {sorted(override)}")
        return override, quarter_ranges
    if active:
        debug_info(f"Detected current quarter(s) by date: {sorted(active)}")
        return active, quarter_ranges
    if available:
        fallback = {max(available)}
        debug_info(f"No current quarter detected; defaulting to highest available: {fallback}")
        return fallback, quarter_ranges
    return set(), quarter_ranges


def format_quarter_label(quarters: Set[int], ranges: Dict[int, Tuple[Optional[datetime], Optional[datetime]]]) -> str:
    if not quarters:
        return ""
    ordered = sorted(quarters)
    if len(ordered) == 1:
        base = f", четверть {ordered[0]}"
    else:
        base = ", четверти " + ", ".join(str(item) for item in ordered)
    range_str = format_quarter_range(ordered, ranges)
    return base + range_str


def format_quarter_range(ordered_quarters: List[int], ranges: Dict[int, Tuple[Optional[datetime], Optional[datetime]]]) -> str:
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    for q in ordered_quarters:
        range_pair = ranges.get(q)
        if not range_pair:
            continue
        s, e = range_pair
        if s:
            start = s if start is None or s < start else start
        if e:
            end = e if end is None or e > end else end
    parts: List[str] = []
    if start:
        parts.append(start.strftime("%d.%m.%y"))
    if end:
        parts.append(end.strftime("%d.%m.%y"))
    if parts:
        connector = " - " if len(parts) == 2 else ""
        return f" ({connector.join(parts)})"
    return ""


def collect_debts_with_quarters(data: Optional[Dict[str, Any]]) -> Tuple[Dict[str, List[DebtItem]], Set[int], Dict[int, Tuple[Optional[datetime], Optional[datetime]]]]:
    results: Dict[str, List[DebtItem]] = defaultdict(list)
    if not isinstance(data, dict):
        return results, set(), {}
    response = data.get("response", [])
    if not isinstance(response, list):
        return results, set(), {}

    allowed_quarters, quarter_ranges = determine_quarter_info(data)
    if allowed_quarters:
        debug_info(f"Filtering quarters to: {sorted(allowed_quarters)}")
    return_quarters = allowed_quarters
    now = datetime.now(timezone.utc)

    for entry in response:
        if not isinstance(entry, dict):
            continue
        program = entry.get("program", {})
        subject = ""
        if isinstance(program, dict):
            subject = (program.get("name") or "").strip()
        subject = sanitize_subject_name(subject)
        subject = subject or "(неизвестный предмет)"

        study_year = entry.get("studyYear", {})
        if not isinstance(study_year, dict):
            continue
        study_quarters = study_year.get("studyQuarters", [])
        if not isinstance(study_quarters, list):
            continue
        for quarter in study_quarters:
            if not isinstance(quarter, dict):
                continue
            quarter_number = parse_quarter_number(quarter.get("quarterNumber"))
            if allowed_quarters and (quarter_number is None or quarter_number not in allowed_quarters):
                continue
            study_weeks = quarter.get("studyWeeks", [])
            if not isinstance(study_weeks, list):
                continue
            for week in study_weeks:
                if not isinstance(week, dict):
                    continue
                week_end = normalize_datetime_for_compare(parse_iso_datetime(week.get("dateEnd")))
                week_ended = week_end is not None and week_end <= now
                grades = week.get("grades", [])
                if not isinstance(grades, list):
                    continue
                for grade_item in grades:
                    if not isinstance(grade_item, dict):
                        continue
                    is_not_sent = False
                    status = grade_item.get("status")
                    if isinstance(status, str) and status.upper() == "NOT_SENT":
                        if not week_ended:
                            continue
                        code = "Не отправил"
                        is_not_sent = True
                    else:
                        code = None
                    color = normalize_color(grade_item.get("color"))
                    if code is None:
                        code = DEBT_COLOR_MAP.get(color)
                    grade_value = grade_item.get("grade")
                    item_type = grade_item.get("type")
                    if code:
                        if DEBT_GRADE_VALUES and not is_not_sent:
                            if not isinstance(grade_value, int) or grade_value not in DEBT_GRADE_VALUES:
                                continue
                    else:
                        if (
                            isinstance(item_type, str)
                            and item_type.upper() == "CONTROL_TEST"
                            and isinstance(grade_value, int)
                            and grade_value in CONTROL_TEST_DEBT_GRADES
                        ):
                            code = "Незачет"
                        else:
                            continue
                    material = grade_item.get("materialName") or grade_item.get("name") or "Работа"
                    if not isinstance(material, str):
                        material = "Работа"
                    material = material.strip()
                    comment = grade_item.get("comment")
                    if not isinstance(comment, str) or not comment.strip():
                        comment = None
                    results[subject].append(
                        DebtItem(code=code, comment=comment, text=material)
                    )
    return results, return_quarters, quarter_ranges


def collect_debts(data: Dict[str, Any]) -> Dict[str, List[DebtItem]]:
    debts, _, _ = collect_debts_with_quarters(data)
    return debts


def summarize_debts(debts: Dict[str, List[DebtItem]]) -> List[str]:
    lines, _, _ = summarize_debts_with_total(debts)
    return lines


def summarize_debts_with_total(debts: Dict[str, List[DebtItem]]) -> Tuple[List[str], int, Counter[str]]:
    if not debts:
        return ["Долгов нет."], 0, Counter()
    lines: List[str] = []
    total_debts = 0
    total_counter: Counter[str] = Counter()
    for subject in sorted(debts.keys()):
        items = debts[subject]
        counts = Counter([item.code for item in items])
        total_counter.update(counts)
        subject_total = sum(counts.values())
        total_debts += subject_total
        line = f"{subject}: Долгов x{subject_total}"
        if counts:
            count_parts = [f"{code} x{counts[code]}" for code in sorted(counts.keys())]
            line += " (" + ", ".join(count_parts) + ")"
        if SEND_COMMENTS:
            comments = [
                f"{item.text}: {item.comment}" if item.comment else None for item in items
            ]
            comments = [value for value in comments if value]
            if comments:
                unique_comments = list(dict.fromkeys(comments))
                line += " | Комментарии: " + " ; ".join(unique_comments)
        lines.append(line)
    return lines, total_debts, total_counter


def build_message(student_name: str, debts: Dict[str, List[DebtItem]], quarters: Set[int], quarter_ranges: Dict[int, Tuple[Optional[datetime], Optional[datetime]]]) -> str:
    label = format_quarter_label(quarters, quarter_ranges)
    lines = [f"Ученик: {student_name}{label}"]
    summary_lines, total, total_counter = summarize_debts_with_total(debts)
    lines.extend(summary_lines)
    total_line = f"ИТОГО: Долгов x{total}"
    if total_counter:
        parts = [f"{code} x{total_counter[code]}" for code in sorted(total_counter.keys())]
        total_line += " (" + ", ".join(parts) + ")"
    lines.append(total_line)
    return "\n".join(lines)


def process_student(student: Dict[str, str]) -> Tuple[str, str, Dict[str, List[DebtItem]], Set[int], Dict[int, Tuple[Optional[datetime], Optional[datetime]]]]:
    name = student.get("name") or "Без имени"
    login_name = student.get("login")
    password = student.get("password")
    if not login_name or not password:
        raise SystemExit(f"Missing login/password for student: {name}")

    ensure_data_dir()
    session = requests.Session()
    token_file = token_path(name, login_name)
    tokens = load_tokens(session, token_file)
    had_tokens = tokens is not None
    debug_info(f"Tokens for {name!r} loaded: {had_tokens}, file={token_file}")
    cache_file = grades_cache_path(name, login_name)
    data = load_cached_grades(cache_file)
    if data is not None:
        debug_info("Skipping network fetch because cached grades are fresh")
        debts, allowed_quarters, quarter_ranges = collect_debts_with_quarters(data)
        return name, login_name, debts, allowed_quarters, quarter_ranges

    try:
        data = fetch_grades(session)
    except PermissionError:
        debug_info("Received PermissionError, forcing login")
        authenticate(session, login_name, password, token_file)
        data = fetch_grades(session)
    except requests.HTTPError:
        if had_tokens:
            debug_info("HTTPError after load; retrying login")
            authenticate(session, login_name, password, token_file)
            data = fetch_grades(session)
        else:
            raise

    save_grades_cache(cache_file, data)
    debts, allowed_quarters, quarter_ranges = collect_debts_with_quarters(data)
    return name, login_name, debts, allowed_quarters, quarter_ranges


def main() -> int:
    students = parse_students()
    if not students:
        print(f"No students in {SETTINGS_FILE}.")
        return 1

    messages = []
    for student in students:
        name, login_name, debts, quarters, quarter_ranges = process_student(student)
        text = build_message(name, debts, quarters, quarter_ranges)
        messages.append(text)
        notify_change(name, login_name, text)

    text = "\n\n".join(messages)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
