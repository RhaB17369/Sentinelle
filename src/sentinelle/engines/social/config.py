import os

# List directory
LIST_DIRECTORY = os.path.join(os.path.dirname(__file__), "resources")

# Username List
USERNAME_LIST_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
USERNAME_LIST_FILENAME = "wmn-data.json"
USERNAME_LIST_PATH = os.path.join(LIST_DIRECTORY, USERNAME_LIST_FILENAME)
USERNAME_METADATA_LIST_FILENAME = "wmn-metadata.json"
USERNAME_METADATA_LIST_PATH = os.path.join(
    LIST_DIRECTORY, USERNAME_METADATA_LIST_FILENAME
)

# Email List
EMAIL_LIST_FILENAME = "email-data.json"
EMAIL_LIST_PATH = os.path.join(LIST_DIRECTORY, EMAIL_LIST_FILENAME)

# Logs
LOG_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "logs")
LOG_FILENAME = "sentinelle.log"
LOG_PATH = os.path.join(LOG_DIRECTORY, LOG_FILENAME)

# Assets
ASSETS_DIRECTORY = "assets"
FONTS_DIRECTORY = "fonts"
IMAGES_DIRECTORY = "img"


# PDF
FONT_REGULAR_FILE = "Montserrat-Regular.ttf"
FONT_BOLD_FILE = "Montserrat-Bold.ttf"
FONT_NAME_REGULAR = "Montserrat"
FONT_NAME_BOLD = "Montserrat-Bold"

aiModel = None
ai_analysis = None