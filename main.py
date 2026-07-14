from app.db import (
    get_all_dead_letters,
    get_all_events,
    initialize_database,
    save_dead_letter,
    save_event,
)
from app.normalize import normalize_event
from app.validate import validate_event

raw_events = [
    {
        "id": "evt_001",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:00:00Z",
        "actor": {
            "alternateId": "user1@company.com"
        },
        "client": {
            "ipAddress": "203.0.113.50"
        },
        "outcome": {
            "result": "FAILURE"
        }
    },
    {
        "id": "aws_001",
        "source": "aws",
        "eventTime": "2026-07-10T18:05:00Z",
        "eventName": "StopLogging",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/admin"
        },
        "sourceIPAddress": "198.51.100.10"
    },
    {
        "id": "evt_broken",
        "source": "okta",
        "eventType": "user.authentication.failed",
        # This event is intentionally missing "published"
        "actor": {
            "alternateId": "broken@company.com"
        },
        "client": {
            "ipAddress": "203.0.113.99"
        },
        "outcome": {
            "result": "FAILURE"
        }
    }
]

def process_event(raw_event: dict) -> None:
    """
        Normalizes, validates, and stores one raw security event
    """

    normalized_event = normalize_event(raw_event)

    is_valid, missing_fields = validate_event(normalized_event)

    if is_valid:
        save_event(normalized_event)
        print(f"Saved event: {normalized_event['event_id']}")
    else:
        save_dead_letter(normalized_event, missing_fields)
        print(f"Deadlettered event: {normalized_event.get('event_id')} " f"missing={missing_fields}")

def main():
    initialize_database()

    for raw_event in raw_events:
        process_event(raw_event)

    print("\nValid events in SIEM:")
    for event in get_all_events():
        print(event)

    print("\nDead-lettered events:")
    for dead_letter in get_all_dead_letters():
        print(dead_letter)

if __name__ == "__main__":
    main()