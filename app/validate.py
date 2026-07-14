from typing import Any

REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "action",
}

def validate_event(event: dict[str, Any]) -> tuple[bool, list[str]]:
    """
        Check whether a normalized event has the minimum fields required for our SIEM

        Returns:
            (True, [])
            (False, ["missing_field_1", ...]) if invalid
    """

    missing_fields = []

    for field in REQUIRED_FIELDS:
        if not event.get(field):
            missing_fields.append(field)

    is_valid = len(missing_fields) == 0

    return is_valid, missing_fields