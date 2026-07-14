from fastapi import FastAPI, HTTPException, Query

app = FastAPI(title="Mock Security Source API")

SAMPLE_EVENTS = [
    {
        "id": "okta_001",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:00:00Z",
        "actor": {"alternateId": "user1@company.com"},
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "okta_002",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:01:00Z",
        "actor": {"alternateId": "user2@company.com"},
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "okta_003",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:02:00Z",
        "actor": {"alternateId": "user3@company.com"},
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "okta_004",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:03:00Z",
        "actor": {"alternateId": "user4@company.com"},
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "okta_005",
        "source": "okta",
        "eventType": "user.authentication.failed",
        "published": "2026-07-10T18:04:00Z",
        "actor": {"alternateId": "user5@company.com"},
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "okta_006",
        "source": "okta",
        "eventType": "user.authentication.succeeded",
        "published": "2026-07-10T18:05:00Z",
        "actor": {"alternateId": "user1@company.com"},
        "client": {
            "ipAddress": "198.51.100.80",
            "geographicalContext": {"country": "US"},
        },
        "outcome": {"result": "SUCCESS"},
    },
    {
        "id": "okta_broken_001",
        "source": "okta",
        "eventType": "user.authentication.failed",
        # intentionally missing published timestamp
        "actor": {"alternateId": "broken@company.com"},
        "client": {"ipAddress": "203.0.113.99"},
        "outcome": {"result": "FAILURE"},
    },
    {
        "id": "aws_001",
        "source": "aws",
        "eventTime": "2026-07-10T18:10:00Z",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/admin",
        },
        "sourceIPAddress": "198.51.100.10",
    },
    {
        "id": "aws_002",
        "source": "aws",
        "eventTime": "2026-07-10T18:12:00Z",
        "eventName": "StopLogging",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/admin",
        },
        "sourceIPAddress": "198.51.100.10",
    },
    {
        "id": "aws_003",
        "source": "aws",
        "eventTime": "2026-07-10T18:14:00Z",
        "eventName": "CreateAccessKey",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/admin",
        },
        "sourceIPAddress": "198.51.100.10",
    },
    {
        "id": "aws_broken_001",
        "source": "aws",
        "eventTime": "2026-07-10T18:15:00Z",
        # intentionally missing eventName/action
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/test",
        },
        "sourceIPAddress": "198.51.100.22",
    },
]

@app.get("/")
def root():
    return {
        "message": "Mock Security Source API is running",
        "example": "/source/events?source=okta&cursor=0&limit=5",
    }

@app.get("/source/events")
def get_events(
    source: str | None = None,
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=5, ge=1, le=50),
    simulate_500: bool = False,
    simulate_429: bool = False,
):
    """
        Return fake security events with simple cursor pagination.

        cursor:
            Starting index.

        limit:
            Number of events to return.

        source:
            Optional filter. Use "okta" or "aws".
    """

    if simulate_500:
        raise HTTPException(status_code=500, detail="Simulated source API failure")
    
    if simulate_429:
        raise HTTPException(
            status_code=429,
            detail="Simulated rate limit",
            headers={"Retry-After": "2"},
        )
    
    if source:
        filtered_events = [
            event for event in SAMPLE_EVENTS
            if event.get("source") == source
        ]
    else:
        filtered_events = SAMPLE_EVENTS

    start = cursor
    end = cursor + limit

    page = filtered_events[start:end]

    next_cursor = str(end) if end < len(filtered_events) else None

    return {
        "events": page,
        "count": len(page),
        "end_cursor": str(end),
        "next_cursor": next_cursor,
        "total_available": len(filtered_events),
    }