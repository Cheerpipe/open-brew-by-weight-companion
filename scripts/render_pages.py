"""Render every companion page as it is served, for html-validate.

Usage: PYTHONPATH=<repo>:<repo>/gateway python scripts/render_pages.py OUT_DIR

The pages come from the production code (gateway.setup_pages and
companion.service.render_page) with sample values (real QR codes) in place of the ones a
running companion fills in: the setup page in every language of
gateway/strings.json, the companion page, and the Web UI notice.
"""

import sys
from pathlib import Path

import gateway
from companion import service

SETUP_URL = "http://openbrewbyweight-secure.local"
SAMPLE = {
    "SECURE_URL": "https://openbrewbyweight-secure.local",
    "NAME": "Kitchen server",
    "VERSION": "1.0.0+0123abc",
    "HOSTNAME": "openbrewbyweight-secure.local",
    "CA_NAME": gateway.CA_NAME,
    "FINGERPRINT": ":".join(["AB"] * 32),
    "QR": gateway.qr_svg(SETUP_URL),
    "QR_IOS": gateway.qr_svg(f"{SETUP_URL}/{gateway.CA_NAME}.mobileconfig"),
    "QR_ANDROID": gateway.qr_svg(f"{SETUP_URL}/{gateway.CA_NAME}.crt"),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    target = ("Cafe Bar", ("192.168.1.50", 80))
    pages = {
        "companion.html": service.render_page(),
        "ui-off.html": service.notice_page("Kitchen server").replace(
            "@ADDRESS@", "http://192.168.1.50"
        ),
    }
    for lang, page in gateway.setup_pages(SAMPLE, target).items():
        pages[f"setup.{lang}.html"] = page
    pages["setup.looking.html"] = gateway.setup_pages(SAMPLE, None)["en"]
    for name, page in pages.items():
        (out / name).write_text(page)
        print(f"rendered {out / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
