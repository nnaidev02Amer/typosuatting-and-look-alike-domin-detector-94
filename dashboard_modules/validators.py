"""Target-domain validation. Output is safe to pass as a single argv element."""
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


def validate_domain(raw):
    """Return (ok, normalized_domain, message).

    Accepts a bare domain name (a leading http(s):// and any trailing path are
    stripped). Spaces, option-like input, shell metacharacters, IP addresses
    and single labels are rejected. The normalized value is the lower-case
    ASCII (punycode) form.
    """
    if raw is None or not str(raw).strip():
        return False, "", "Enter a domain name, for example example.com."
    value = str(raw).strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rstrip(".")
    if not value:
        return False, "", "Enter a domain name, for example example.com."
    if value.startswith("-"):
        return False, "", "A domain name cannot start with '-'."
    if re.search(r"\s", value):
        return False, "", "A domain name cannot contain spaces."
    if ":" in value or "@" in value:
        return False, "", "Enter only a domain name (no port, credentials or other arguments)."
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "", "The domain contains characters that cannot be converted to a valid internationalized (IDNA) name."
    if len(ascii_name) > 253:
        return False, "", "The domain is longer than 253 characters."
    labels = ascii_name.split(".")
    if len(labels) < 2:
        return False, "", "Enter a fully qualified domain such as example.com (at least two labels)."
    for label in labels:
        if not _LABEL.match(label):
            return False, "", "Invalid label '{}': use letters, digits and hyphens (no leading/trailing hyphen, max 63 characters).".format(label[:40])
    if not _TLD.match(labels[-1]):
        return False, "", "Invalid top-level domain '{}'.".format(labels[-1][:40])
    return True, ascii_name, "Valid domain."
