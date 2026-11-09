"""Lumoth Uploader: a single-channel YouTube client (standard library only).

python youtube.py connect         sign in with Google (needs secrets/client_secret.json)
python youtube.py upload FILE     upload a video: asks for title, description and privacy, then confirms
python youtube.py disconnect      revoke access at Google and delete everything stored from the API
python youtube.py                 show whether a login is stored
"""
import base64
import csv
import hashlib
import http.server
import json
import os
import secrets as token_tools
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(os.environ.get("LUMOTH_ROOT", Path(__file__).resolve().parent.parent))
SITE = "https://11vz.github.io/lumoth"
NOTICE = ("Lumoth Uploader uses YouTube API Services. By continuing you agree to the YouTube Terms of Service "
          f"(https://www.youtube.com/t/terms) and the Lumoth Uploader privacy policy ({SITE}/privacy.html).")
SECRETS = Path(os.environ.get("LUMOTH_SECRETS", ROOT / "secrets"))
CLIENT_FILE = SECRETS / "client_secret.json"
TOKEN_FILE = SECRETS / "token.json"
PENDING_FILE = SECRETS / "pending_consent.json"
PHONE_REDIRECT = "http://127.0.0.1:8765"
EXPECTED_CHANNEL = "Lumoth"
SCOPES = ["https://www.googleapis.com/auth/youtube.upload",
          "https://www.googleapis.com/auth/youtube.readonly",
          "https://www.googleapis.com/auth/yt-analytics.readonly"]
TOKEN_URL = os.environ.get("LUMOTH_TOKEN_URL", "https://oauth2.googleapis.com/token")
REVOKE_URL = os.environ.get("LUMOTH_REVOKE_URL", "https://oauth2.googleapis.com/revoke")
API = os.environ.get("LUMOTH_API", "https://www.googleapis.com")
ANALYTICS = os.environ.get("LUMOTH_ANALYTICS", "https://youtubeanalytics.googleapis.com")
CHUNK = 8 * 1024 * 1024
RETRYABLE = {500, 502, 503, 504}
MAX_TITLE = 100
MAX_DESCRIPTION_BYTES = 5000
PRIVACY_CHOICES = ("public", "unlisted", "private")


class NotConnected(RuntimeError):
    pass


class WrongChannel(RuntimeError):
    pass


def is_connected():
    return TOKEN_FILE.exists()


def _client():
    if not CLIENT_FILE.exists():
        raise NotConnected(f"missing {CLIENT_FILE}")
    data = json.loads(CLIENT_FILE.read_text())
    return data.get("installed") or data.get("web")


def _post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, method="POST")) as response:
        return json.loads(response.read())


def _new_challenge():
    verifier = token_tools.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge, token_tools.token_urlsafe(16)


def _consent_url(client, redirect, state, challenge):
    return client["auth_uri"] + "?" + urllib.parse.urlencode({
        "client_id": client["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": " ".join(SCOPES),
        "access_type": "offline", "prompt": "select_account consent", "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256"})


def _store_token(client, code, redirect, verifier):
    token = _post_form(TOKEN_URL, {"code": code, "client_id": client["client_id"], "client_secret": client.get("client_secret", ""),
                                   "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier})
    token["expires_at"] = time.time() + token.get("expires_in", 3600) - 60
    SECRETS.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(token))


def verify_channel():
    """The owner's Google login can reach several real channels; this refuses every one but Lumoth."""
    title = channel()["snippet"]["title"]
    if title.strip().lower() != EXPECTED_CHANNEL.lower():
        raise WrongChannel(f"signed in as '{title}', expected '{EXPECTED_CHANNEL}'")
    return title


def _confirm_connected():
    try:
        print("Connected:", verify_channel())
    except WrongChannel as error:
        TOKEN_FILE.unlink(missing_ok=True)
        raise RuntimeError(f"{error}. Access was not saved. Sign in again and pick {EXPECTED_CHANNEL}.") from error


def phone_start():
    """First half of consent from another device: prints the link and keeps the PKCE verifier on this PC."""
    client = _client()
    verifier, challenge, state = _new_challenge()
    PENDING_FILE.write_text(json.dumps({"verifier": verifier, "state": state}))
    print(NOTICE, file=sys.stderr)
    print(_consent_url(client, PHONE_REDIRECT, state, challenge))


def phone_finish(pasted):
    """Second half: the phone lands on an unreachable 127.0.0.1 page whose address holds a one-time code."""
    if not PENDING_FILE.exists():
        raise RuntimeError("no sign-in in progress; run phone-start first")
    pending = json.loads(PENDING_FILE.read_text())
    query = urllib.parse.parse_qs(urllib.parse.urlparse(pasted.strip()).query)
    if "error" in query:
        raise RuntimeError(f"consent refused: {query['error'][0]}")
    if query.get("state", [""])[0] != pending["state"] or "code" not in query:
        raise RuntimeError("that address does not match this sign-in; run phone-start again")
    _store_token(_client(), query["code"][0], PHONE_REDIRECT, pending["verifier"])
    PENDING_FILE.unlink()
    _confirm_connected()


def connect():
    """Browser consent on a loopback redirect. The refresh token is stored only in secrets/."""
    client = _client()
    verifier, challenge, state = _new_challenge()
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            received.update({k: v[0] for k, v in query.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Lumoth is connected. You can close this tab.")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    redirect = f"http://127.0.0.1:{server.server_address[1]}"
    url = _consent_url(client, redirect, state, challenge)
    print(NOTICE)
    print("Opening your browser. If nothing appears, visit:\n" + url)
    webbrowser.open(url)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    thread.join()
    server.server_close()
    if received.get("state") != state or "code" not in received:
        raise RuntimeError(f"consent failed: {received.get('error', 'state mismatch')}")
    _store_token(client, received["code"], redirect, verifier)
    _confirm_connected()


def _access_token():
    if not TOKEN_FILE.exists():
        raise NotConnected(f"missing {TOKEN_FILE}; run: python youtube.py connect")
    token = json.loads(TOKEN_FILE.read_text())
    if time.time() >= token.get("expires_at", 0):
        client = _client()
        try:
            fresh = _post_form(TOKEN_URL, {"refresh_token": token["refresh_token"], "client_id": client["client_id"],
                                           "client_secret": client.get("client_secret", ""), "grant_type": "refresh_token"})
        except urllib.error.HTTPError as error:
            if error.code in (400, 401):  # an app still in Testing loses its login after 7 days
                raise NotConnected("login expired; approve access again with phone-start") from error
            raise
        token.update(fresh)
        token["expires_at"] = time.time() + fresh.get("expires_in", 3600) - 60
        TOKEN_FILE.write_text(json.dumps(token))
    return token["access_token"]


def _get(base, path, params):
    url = f"{base}{path}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {_access_token()}"})
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def channel():
    items = _get(API, "/youtube/v3/channels", {"part": "snippet,statistics,contentDetails,status", "mine": "true"}).get("items", [])
    if not items:
        raise RuntimeError("this Google account has no YouTube channel")
    return items[0]


def uploads(limit=200):
    playlist = channel()["contentDetails"]["relatedPlaylists"]["uploads"]
    ids, page = [], None
    while len(ids) < limit:
        params = {"part": "contentDetails", "playlistId": playlist, "maxResults": 50}
        if page:
            params["pageToken"] = page
        data = _get(API, "/youtube/v3/playlistItems", params)
        ids += [i["contentDetails"]["videoId"] for i in data.get("items", [])]
        page = data.get("nextPageToken")
        if not page:
            break
    return videos_by_id(ids)


def videos_by_id(ids):
    """Only videos that still exist come back, so a missing id means the video is gone."""
    videos = []
    for i in range(0, len(ids), 50):
        videos += _get(API, "/youtube/v3/videos", {"part": "snippet,contentDetails,status,statistics",
                                                   "id": ",".join(ids[i: i + 50])}).get("items", [])
    return videos


def analytics_by_video(start, end):
    metrics = "views,estimatedMinutesWatched,averageViewDuration,averageViewPercentage,likes,comments,shares,subscribersGained"
    data = _get(ANALYTICS, "/v2/reports", {"ids": "channel==MINE", "startDate": start, "endDate": end, "metrics": metrics,
                                           "dimensions": "video", "sort": "-views", "maxResults": 200})
    names = [h["name"] for h in data.get("columnHeaders", [])]
    return {row[0]: dict(zip(names[1:], row[1:])) for row in data.get("rows", [])}


def _authorized_request(url, data, headers, method):
    return urllib.request.Request(url, data, {"Authorization": f"Bearer {_access_token()}", **headers}, method=method)


def check_metadata(title, description, privacy):
    """YouTube's limits. Values are refused rather than shortened, because the API policies forbid altering them."""
    if not title.strip() or len(title) > MAX_TITLE:
        raise ValueError(f"title must be 1 to {MAX_TITLE} characters, got {len(title)}")
    if len(description.encode("utf-8")) > MAX_DESCRIPTION_BYTES:
        raise ValueError(f"description must be at most {MAX_DESCRIPTION_BYTES} bytes")
    if set("<>") & set(title + description):
        raise ValueError("YouTube does not accept < or > in titles or descriptions")
    if privacy not in PRIVACY_CHOICES:
        raise ValueError(f"privacy must be one of {PRIVACY_CHOICES}")


def upload(path, title, description, tags, privacy="public", category="10"):
    """Resumable upload. Returns the created video resource, including the privacy YouTube actually applied."""
    check_metadata(title, description, privacy)
    verify_channel()
    path = Path(path)
    size = path.stat().st_size
    body = {"snippet": {"title": title, "description": description, "tags": tags, "categoryId": category},
            "status": {"privacyStatus": privacy, "selfDeclaredMadeForKids": False, "embeddable": True}}
    request = _authorized_request(
        f"{API}/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status", json.dumps(body).encode(),
        {"Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Length": str(size),
         "X-Upload-Content-Type": "video/mp4"}, "POST")
    with urllib.request.urlopen(request) as response:
        session = response.headers["Location"]
    sent, attempts = 0, 0
    with path.open("rb") as stream:
        while sent < size:
            stream.seek(sent)
            chunk = stream.read(CHUNK)
            request = _authorized_request(session, chunk, {"Content-Type": "video/mp4", "Content-Length": str(len(chunk)),
                                                           "Content-Range": f"bytes {sent}-{sent + len(chunk) - 1}/{size}"}, "PUT")
            try:
                with urllib.request.urlopen(request) as response:
                    return json.loads(response.read())
            except urllib.error.HTTPError as error:
                if error.code == 308:
                    received = error.headers.get("Range")
                    sent = int(received.split("-")[1]) + 1 if received else 0
                    attempts = 0
                    continue
                if error.code in RETRYABLE and attempts < 6:
                    attempts += 1
                    time.sleep(2 ** attempts)
                    continue
                raise RuntimeError(f"upload failed {error.code}: {error.read()[:500]!r}") from error
    raise RuntimeError("upload ended without a response")


def upload_interactively(path):
    """The flow a person sees: which channel, exactly what will be sent, and nothing happens until they say yes."""
    name = verify_channel()
    print(f"{NOTICE}\n\nChannel: {name}\nFile: {path}")
    title = input("Title: ").strip()
    description = input("Description: ").strip()
    privacy = ""
    while privacy not in PRIVACY_CHOICES:
        privacy = input("Privacy (public, unlisted or private): ").strip().lower()
    if input(f"Upload this to {name} as {privacy}? Type yes to confirm: ").strip().lower() != "yes":
        print("Cancelled. Nothing was uploaded.")
        return None
    video = upload(path, title, description, [], privacy)
    print(f"Uploaded: https://youtu.be/{video['id']}\nPrivacy requested: {privacy}\n"
          f"Privacy YouTube applied: {video.get('status', {}).get('privacyStatus')}")
    return video


def delete_api_data():
    """Removes everything kept from the API: audit reports, logged video ids and statuses, and learned weights."""
    shutil.rmtree(ROOT / "audits", ignore_errors=True)
    log = ROOT / "learning" / "log.csv"
    if log.exists():
        with log.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fields, rows = reader.fieldnames, list(reader)
        for row in rows:
            row.update(video_id="", actual_privacy="")
        with log.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fields)
            writer.writeheader()
            writer.writerows(rows)
    strategy_file = ROOT / "learning" / "strategy.json"
    if strategy_file.exists():
        strategy = json.loads(strategy_file.read_text())
        for key in ("modes", "palettes", "hooks", "title_templates"):
            strategy[key] = {option: 1.0 for option in strategy[key]}
        strategy_file.write_text(json.dumps(strategy, indent=1))


def disconnect():
    """Revokes the login at Google first, so access ends even if the local cleanup is interrupted."""
    if TOKEN_FILE.exists():
        token = json.loads(TOKEN_FILE.read_text())
        request = urllib.request.Request(REVOKE_URL, urllib.parse.urlencode(
            {"token": token.get("refresh_token") or token["access_token"]}).encode(), method="POST")
        try:
            urllib.request.urlopen(request).close()
        except urllib.error.HTTPError as error:
            if error.code != 400:  # 400 means Google already treats the token as revoked or expired
                raise
        TOKEN_FILE.unlink()
    delete_api_data()
    print("Access revoked. The login and all stored YouTube data were deleted.")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "connect":
        connect()
    elif command == "phone-start":
        phone_start()
    elif command == "phone-finish":
        phone_finish(sys.argv[2])
    elif command == "upload":
        upload_interactively(sys.argv[2])
    elif command == "disconnect":
        if input("Revoke access and delete all stored YouTube data? Type yes to confirm: ").strip().lower() == "yes":
            disconnect()
        else:
            print("Cancelled.")
    else:
        print("connected" if is_connected() else "not connected")
