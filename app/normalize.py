from typing import Any

def normalize_okta_event(raw_event: dict[str,Any]) -> dict[str, Any]:
    # Convert an Okta-style raw event into our normalzied SIEM event schema

    """
        Raw Okta field examples:
        - id
        - published
        - eventType
        - actor.alternateId
        - client.ipAddress
        - outcome.result

        Normalized fields:
        - event_id
        - timestamp
        - source
        - event_type
        - action
        - outcome
        - user
        - source_ip
        - raw
    """
    event_type = raw_event.get("eventType", "")

    if "authentication" in event_type:
        normalized_event_type = "authentication"
    else:
        normalized_event_type = "unknown"

    if "failed" in event_type or "success" in event_type:
        action = "login"
    else:
        action = "unknown"

    actor = raw_event.get("actor") or {}
    client = raw_event.get("client") or {}
    outcome = raw_event.get("outcome") or {}

    return {
        "event_id": raw_event.get("id"),
        "timestamp": raw_event.get("published"),
        "source": "okta",
        "event_type": normalized_event_type,
        "action": action,
        "outcome": str(outcome.get("result", "unknown")).lower(),
        "user": actor.get("alternateId"),
        "source_ip": client.get("ipAddress"),
        "raw": raw_event,
    }

def normalize_aws_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """
        Convert an AWS CloudTrail raw event into the normalized SIEM event schema
    """

    user_identity = raw_event.get("user_identity") or {}

    return {
        "event_id": raw_event.get("id"),
        "timestamp": raw_event.get("eventTime"),
        "source": "aws",
        "event_type": "cloudtrail",
        "action": raw_event.get("eventName"),
        "outcome": "unknown",
        "user": user_identity.get("arn"),
        "source_ip": raw_event.get("sourceIPAddress"),
        "raw": raw_event,
    }

def normalize_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """
        Route the event to the correct normalization
    """

    source = raw_event.get("source")

    if source == "okta":
        return normalize_okta_event(raw_event)
    
    if source == "aws":
        return normalize_aws_event(raw_event)
    
    return {
        "event_id": raw_event.get("id"),
        "timestamp": None,
        "source": source or "unknown",
        "event_type": "unknown",
        "action": "unknown",
        "outcome": "unknown",
        "user": None,
        "source_ip": None,
        "raw": raw_event,
    }