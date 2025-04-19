import logging
import re
import json
import httpx

REFLECTED_XSS_CHEAT_SHEET_DATA_URL = "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet-data.js"
REFLECTED_XSS_CHEAT_SHEET_REGEX = r"var\s+data\s+=\s+({.*})"

def get_reflected_xss_payloads():

    payloads = []

    try:
        response = httpx.get(REFLECTED_XSS_CHEAT_SHEET_DATA_URL, timeout=1)

        match = re.search(REFLECTED_XSS_CHEAT_SHEET_REGEX, response.text)

        if match:
            data_json_string = match.group(1).strip()
            cheat_sheet_json_obj = json.loads(data_json_string)
            for key in cheat_sheet_json_obj:
                payloads.append(cheat_sheet_json_obj[key]["tags"][0]["code"])
        else:
            logging.info("No match!")

    except Exception as e:
        logging.exception("Exception during PortSwigger Reflected XSS payloads retrieval from official website: %s", e)

    return payloads
