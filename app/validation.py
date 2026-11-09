"""Input validation: presence, type, length, format. Failures become a clean 400."""
import re
import uuid

from flask import request

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
# Any of these keys in a body is an attempt to choose a privilege -> 403.
PRIVILEGE_KEYS = {"role", "roles", "is_admin", "isadmin", "admin", "permissions", "is_superuser"}


class ValidationError(Exception):
    pass


class Forbidden(Exception):
    pass


def parse_body(allowed):
    """Return the JSON object body, rejecting non-JSON, non-objects and unknown fields."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("body must be a JSON object")
    if any(str(k).lower() in PRIVILEGE_KEYS for k in data):
        raise Forbidden("role/privilege fields cannot be set by clients")
    unknown = set(data) - set(allowed)
    if unknown:
        raise ValidationError("unexpected field(s)")
    return data


def _string(data, field, min_len, max_len):
    value = data.get(field)
    if value is None:
        raise ValidationError(f"{field} is required")
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if not (min_len <= len(value) <= max_len):
        raise ValidationError(f"{field} must be {min_len}-{max_len} characters")
    return value


def username_field(data):
    value = _string(data, "username", 3, 32).strip().lower()
    if not USERNAME_RE.match(value):
        raise ValidationError("username may only contain a-z, 0-9, '_', '.', '-' (3-32 chars)")
    return value


def password_field(data, min_len):
    # Upper bound stops huge inputs being used to burn CPU/memory in the hash.
    return _string(data, "password", min_len, 128)


def title_field(data):
    value = _string(data, "title", 1, 200)
    if not value.strip():
        raise ValidationError("title must not be blank")
    return value


def body_field(data):
    return _string(data, "body", 1, 10_000)


def record_id_or_none(raw):
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return None
