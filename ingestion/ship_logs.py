"""
ship_logs.py

Read Cowrie's JSON logs and upload them to Azure Blob Storage.

Cowrie writes ONE JSON OBJECT PER LINE (this format is called "JSON Lines").
That's convenient: each line is one event you can json.loads() independently,
and Spark can read the whole file natively later.

Run this on the VM (or pull
the logs down and run it anywhere) on a schedule, e.g. once a day via cron.
"""

import json
import os
from datetime import datetime
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

load_dotenv()  # reads AZURE_STORAGE_CONNECTION_STRING from a local .env file

COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
CONTAINER = "raw-logs"


def read_events(log_path):
    """Read a Cowrie JSON-lines file into a list of dicts.

    This is the same idea as reading rows from a table: each line = one row.
    """
    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue  # skip blank lines
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A half-written last line can happen if Cowrie is mid-write. Skip it.
                continue
    return events


def filter_logins(events):
    """Keep only login attempts.

    Cowrie tags every event with an 'eventid'. Login attempts look like
    'cowrie.login.failed' or 'cowrie.login.success'. Think of this as:
        SELECT * FROM events WHERE eventid LIKE 'cowrie.login%'
    """
    return [e for e in events if e.get("eventid", "").startswith("cowrie.login")]


def upload_to_blob(local_path, blob_name):
    """Upload one file to Blob Storage.

    The connection string comes from an environment variable so you NEVER
    hardcode secrets in code you push to GitHub.
    """
    conn = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    service = BlobServiceClient.from_connection_string(conn)

    # Create the container the first time; ignore the error if it already exists.
    try:
        service.create_container(CONTAINER)
    except Exception:
        pass

    blob = service.get_blob_client(container=CONTAINER, blob=blob_name)
    with open(local_path, "rb") as data:
        blob.upload_blob(data, overwrite=True)
    print(f"Uploaded {local_path} -> {CONTAINER}/{blob_name}")


def main():
    # Give each upload a dated name so history builds up over time:
    #   raw-logs/cowrie-2026-07-12.json
    today = datetime.utcnow().strftime("%Y-%m-%d")
    blob_name = f"cowrie-{today}.json"

    events = read_events(COWRIE_LOG)
    logins = filter_logins(events)
    print(f"Read {len(events)} events, {len(logins)} of them login attempts.")

    # Upload the whole raw file — we keep everything and filter later in Spark.
    upload_to_blob(COWRIE_LOG, blob_name)


if __name__ == "__main__":
    main()
