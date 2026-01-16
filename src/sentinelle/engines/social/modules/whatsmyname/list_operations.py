import os
import sys
import json



from ..utils.http_client import do_sync_request
from ..utils.hash import hashJSON
from ..utils.log import logError
import importlib.resources as resources



def safe_print(config, msg):
    """Print via config.console if available, otherwise fallback to print()."""
    console = getattr(config, "console", None)
    if console:
        try:
            console.print(msg)
            return
        except Exception:
            pass
    print(msg)

# Read list file and return content
def readList(option, config):
    try:
        if option == "username":
            with open(config.USERNAME_LIST_PATH, "r", encoding="UTF-8") as f:
                data = json.load(f)
            return data
        elif option == "email":
            with open(config.EMAIL_LIST_PATH, "r", encoding="UTF-8") as f:
                data = json.load(f)
            return data
        elif option == "metadata":
            with open(config.USERNAME_METADATA_LIST_PATH, "r", encoding="UTF-8") as f:
                data = json.load(f)
            return data
        else:
            return False
    except json.decoder.JSONDecodeError as e:
        # Local file is corrupt or empty — try to fetch a fresh copy
        logError(e, f"Invalid JSON while reading {option} list file", config)
        safe_print(config, ":police_car_light: Local list appears corrupted; attempting to download a fresh copy...")
        if downloadList(config):
            # Try reading again
            try:
                if option == "username":
                    with open(config.USERNAME_LIST_PATH, "r", encoding="UTF-8") as f:
                        return json.load(f)
                elif option == "email":
                    with open(config.EMAIL_LIST_PATH, "r", encoding="UTF-8") as f:
                        return json.load(f)
                elif option == "metadata":
                    with open(config.USERNAME_METADATA_LIST_PATH, "r", encoding="UTF-8") as f:
                        return json.load(f)
            except Exception as e2:
                logError(e2, "Failed to read list after attempting download", config)
                raise RuntimeError("List file is invalid and could not be recovered") from e2
        # If download failed, try bundled fallback resource before failing
        safe_print(config, ":bulb: Using bundled site list fallback")
        try:
            text = resources.files("sentinelle.engines.social").joinpath("resources", "wmn-data.json").read_text()
            return json.loads(text)
        except Exception as e2:
            logError(e2, "Bundled site list fallback unavailable", config)
            raise RuntimeError("List file is invalid and no remote list could be downloaded") from e
    except FileNotFoundError:
        # Local file is missing — try using bundled resource
        safe_print(config, ":bulb: Local site list missing, trying bundled fallback")
        try:
            text = resources.files("sentinelle.engines.social").joinpath("resources", "wmn-data.json").read_text()
            return json.loads(text)
        except Exception as e:
            logError(e, "Bundled site list fallback unavailable", config)
            # Caller should handle missing files (downloadList will create them when possible)
            raise



# Download .JSON file list from defined URL
def downloadList(config):
    response = do_sync_request("GET", config.USERNAME_LIST_URL, config)
    if not response:
        # Network error or request failed
        safe_print(config, ":x: Could not download site list (network error). Please check your connection.")
        return False
    if getattr(response, "status_code", None) != 200:
        safe_print(config, f":x: Failed to download site list (HTTP {response.status_code}).")
        return False
    try:
        data = response.json()
    except Exception as e:
        logError(e, "Downloaded site list is not valid JSON", config)
        safe_print(config, ":x: Downloaded site list is invalid. Aborting update.")
        return False

    # Write only after validating JSON
    try:
        os.makedirs(os.path.dirname(config.USERNAME_LIST_PATH), exist_ok=True)
        with open(config.USERNAME_LIST_PATH, "w", encoding="UTF-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logError(e, "Failed to write site list to disk", config)
        safe_print(config, ":x: Failed to save site list locally.")
        return False


# Check for changes in remote list
def checkUpdates(config):
    if os.path.isfile(config.USERNAME_LIST_PATH):
        safe_print(config, ":counterclockwise_arrows_button: Checking for updates...")
        try:
            data = readList("username", config)
        except Exception as e:
            safe_print(config, ":police_car_light: Coudn't read local list")
            logError(e, f"Coudn't read local list", config)
            safe_print(config, ":down_arrow: Attempting to download site list")
            if not downloadList(config):
                safe_print(config, ":warning: Could not download site list; continuing with current data if available.")
                return
            try:
                data = readList("username", config)
            except Exception as e2:
                logError(e2, "Unable to read site list after download", config)
                safe_print(config, ":x: Unable to load site list after download. Aborting update check.")
                return

        try:
            currentListHash = hashJSON(data)
            response = do_sync_request("GET", config.USERNAME_LIST_URL, config)
            if not response or getattr(response, "status_code", None) != 200:
                safe_print(config, ":warning: Could not fetch remote list; keeping local list")
                return
            try:
                remote_json = response.json()
            except Exception as e:
                logError(e, "Remote list is not valid JSON", config)
                safe_print(config, ":warning: Remote site list invalid; skipping update")
                return

            remoteListHash = hashJSON(remote_json)
            if currentListHash != remoteListHash:
                safe_print(config, ":counterclockwise_arrows_button: Updating...")
                if downloadList(config):
                    safe_print(config, "✔️  Sites List updated")
                else:
                    safe_print(config, ":warning: Update failed")
            else:
                safe_print(config, "✔️  Sites List is up to date")
        except Exception as e:
            logError(e, "Error while checking for updates", config)
            # Don't let update errors break the scan
            safe_print(config, ":warning: Update check failed; proceeding with available list")
    else:
        safe_print(config, ":globe_with_meridians: Downloading site list")
        if not downloadList(config):
            safe_print(config, ":warning: Could not download site list; some features may be limited.")
