import json
import os
from datetime import datetime

LOG_PATH = os.path.join("data", "logs_web.json")

def log_event(
    source,
    level="INFO",
    event_type="EVENT",
    message="",
    component=None,
    context=None
):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": source.lower(),
        "level": level.upper(),
        "event_type": event_type,
        "message": message,
    }

    if component:
        event["component"] = component

    if context:
        event["context"] = context

    os.makedirs("data", exist_ok=True)

    # Initialize file if missing
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w") as f:
            json.dump([], f, indent=2)

    try:
        with open(LOG_PATH, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    logs.append(event)

    with open(LOG_PATH, "w") as f:
        json.dump(logs, f, indent=2)
