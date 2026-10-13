import base64
import ctypes
import hashlib
import hmac
import html
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PKEYCONFIG_DIR = os.path.join(HERE, "pkeyconfig")

HMAC_KEY = bytes.fromhex("fe319875fb4884869cf3f1ce99a89064ab571fca470450583024e214628779a0")
URL = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx"
PKC_NS = {"pkc": "http://www.microsoft.com/DRM/PKEY/Configuration/2.0"}

CUSTOM = "Load Custom PkeyConfig"
AUTO = "Auto-detect / I don't know"

# The original program has no Windows 11 files; the installed Windows carries its own
SYSTEM_PKEYCONFIG_DIR = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "System32", "spp", "tokens", "pkeyconfig")

# Menu label -> pkeyconfig file (bundled name or full path), in the original program's order
PACKAGES = [
    (CUSTOM, None),
    ("Windows 7 / Server 2008 R2", "pkeyconfig_win7"),
    ("Windows 8 / Server 2012", "pkeyconfig_win8"),
    ("Windows 8 / Server 2012 CSVLK", "pkeyconfig_win8csvlk"),
    ("Windows 8.1 / Server 2012 R2", "pkeyconfig_win81"),
    ("Windows 8.1 / Server 2012 R2 CSVLK", "pkeyconfig_win81csvlk"),
    ("Windows 8.1 / Server 2012 R2 preRTM", "pkeyconfig_win81pre"),
    ("Windows 8.1.1 / Server 2012 R2 Update1", "pkeyconfig_win811"),
    ("Windows 8.1.1 / Server 2012 R2 Update1 CSVLK", "pkeyconfig_win811csvlk"),
    ("Windows 10 / Server 2016 (10240)", "pkeyconfig_win10"),
    ("Windows 10 / Server 2016 CSVLK (10240)", "pkeyconfig_win10csvlk"),
    ("Windows 10 / Server 2016 (10586)", "pkeyconfig_win10th2"),
    ("Windows 10 / Server 2016 CSVLK (10586)", "pkeyconfig_win10th2csvlk"),
    ("Windows 10 / Server 2016 RS1 RTM (14393)", "pkeyconfig_win10rs1"),
    ("Windows 10 / Server 2016 RS1 RTM CSVLK (14393)", "pkeyconfig_win10rs1_csvlk"),
    ("Windows 10 / Server 2016 RS2 RTM (15063)", "pkeyconfig_win10rs2"),
    ("Windows 10 / Server 2016 RS2 RTM CSVLK (15063)", "pkeyconfig_win10rs2csvlk"),
    ("Windows 10 / Server 2016 RS3 RTM (16299)", "pkeyconfig_win10rs3"),
    ("Windows 10 / Server 2016 RS3 RTM CSVLK (16299)", "pkeyconfig_win10rs3csvlk"),
    # Not bundled: copy these two from a Windows 11 PC or ISO into the pkeyconfig folder
    ("Windows 11", "pkeyconfig_win11"),
    ("Windows 11 CSVLK", "pkeyconfig_win11csvlk"),
    ("Windows 11 / Windows 10 (this PC's pkeyconfig)", os.path.join(SYSTEM_PKEYCONFIG_DIR, "pkeyconfig.xrm-ms")),
    ("Windows 11 / Windows 10 CSVLK (this PC's pkeyconfig)",
     os.path.join(SYSTEM_PKEYCONFIG_DIR, "pkeyconfig-csvlk.xrm-ms")),
    ("Windows Vista / Server 2008", "pkeyconfig_vista"),
    ("Windows Embedded Standard 7", "pkeyconfig_wes7"),
    ("Windows Embedded Standard 8", "pkeyconfig_wes8"),
    ("Windows Embedded Standard 8 CSVLK", "pkeyconfig_wes8csvlk"),
    ("Windows Embedded Industry Pro 8", "pkeyconfig_we8ipx86"),
    ("Windows Embedded Industry 8.1", "pkeyconfig_win81csvlk"),
    ("Windows Embedded POSReady 7", "pkeyconfig_weposr"),
    ("Windows Embedded Compact 2013", "pkeyconfig_wec2013"),
    ("Windows Home Server 2011", "pkeyconfig_win7"),
    ("Windows Storage Server Essentials 2011", "pkeyconfig_win7"),
    ("Windows Storage Server Essentials 2016", "pkeyconfig_winsse16"),
    ("Windows ThinPC Embedded", "pkeyconfig_tpc_emb"),
    ("Windows ThinPC Embedded Standard", "pkeyconfig_emb_sta"),
    ("Exchange Server 2010", "pkeyconfig_exchange"),
    ("Exchange Server 2013", "pkeyconfig_exchange13"),
    ("Exchange Server 2016", "pkeyconfig_exchange16"),
    ("Office 2010", "pkeyconfig_office14"),
    ("Office 2010 KMS Host", "pkeyconfig_14kmshost"),
    ("Office 2013", "pkeyconfig_office15"),
    ("Office 2013 KMS Host", "pkeyconfig_15kmshost"),
    ("Office 2016", "pkeyconfig_office16"),
    ("Office 2016 KMS Host", "pkeyconfig_16kmshost"),
    ("Office Online Server 2016", "pkeyconfig_officeserver"),
    ("Office Web Apps / Sharepoint Server 2010", "pkeyconfig_officeweb"),
    ("Office Web Apps / Sharepoint Server 2013", "pkeyconfig_officeweb13"),
    ("Office Web Apps / Sharepoint Server 2016", "pkeyconfig_officeweb16"),
    ("Server Essentials 2012 R2", "pkeyconfig_win81"),
    ("Small Business Server 2011", "pkeyconfig_win7"),
    ("Storage Server 2012 R2", "pkeyconfig_win81"),
    ("SQL Server 2012", "pkeyconfig_sql2012"),
    ("SQL Server 2014", "pkeyconfig_sql2014"),
    ("SQL Server 2016", "pkeyconfig_sql2016"),
    ("Visual Studio 2010", "pkeyconfig_vs2010"),
    ("Visual Studio 2012", "pkeyconfig_vs2012"),
    ("Visual Studio 2013", "pkeyconfig_vs2013"),
    ("Visual Studio 2015", "pkeyconfig_vs2015"),
    ("Visual Studio 2017", "pkeyconfig_vs2017"),
]

PIDGENX_ERRORS = {
    0x80070003: "invalid function call / Missing or corrupted file: PIDGENX.DLL",
    0x80070002: "Missing or corrupted file: pkeyconfig.xrm-ms",
    0x80070057: "Invalid arguments / Wrong format",
    0x8A010101: "The specified key does not work with the loaded PKeyConfig file",
}


CYAN, YELLOW, GREEN, DIM, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[2m", "\033[0m"
LOGO_RED, LOGO_GREEN, LOGO_BLUE, LOGO_YELLOW = "\033[101m", "\033[102m", "\033[104m", "\033[103m"

BANNER = rf"""
   {LOGO_RED}      {RESET} {LOGO_GREEN}      {RESET}
   {LOGO_RED}      {RESET} {LOGO_GREEN}      {RESET}   {CYAN}Microsoft{RESET}
   {LOGO_RED}      {RESET} {LOGO_GREEN}      {RESET}

   {LOGO_BLUE}      {RESET} {LOGO_YELLOW}      {RESET}
   {LOGO_BLUE}      {RESET} {LOGO_YELLOW}      {RESET}   {CYAN}Product Key Checker{RESET}
   {LOGO_BLUE}      {RESET} {LOGO_YELLOW}      {RESET}
{GREEN} ==============================================================
{CYAN}                 Microsoft Product Key Checker{GREEN}
 =============================================================={RESET}
   Created by {YELLOW}salnaggar{RESET}        {CYAN}https://github.com/salnaggar{RESET}
{DIM}   Validates Microsoft product keys and checks MAK counts{RESET}
"""


def show_banner():
    os.system("")  # turns on ANSI colors in the Windows console
    print(BANNER)


def ask_key():
    while True:
        key = input("Product Key: ").strip().upper()
        if re.fullmatch(r"[A-Z0-9]{5}(-[A-Z0-9]{5}){4}", key):
            return key
        print("Enter the key as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")


def ask_package():
    print()
    entries = [f"  0. {AUTO}"] + [
        f"{number:3}. {label}" for number, (label, _) in enumerate(PACKAGES, 1)
    ]
    columns = [entries[start:start + 20] for start in range(0, len(entries), 20)]
    widths = [max(len(entry) for entry in column) for column in columns]
    for row in range(min(20, len(entries))):
        cells = [
            (column[row] if row < len(column) else "").ljust(width)
            for column, width in zip(columns, widths)
        ]
        print("    ".join(cells).rstrip())
    while True:
        answer = input(f"\nSoftware Package [0-{len(PACKAGES)}, Enter to auto-detect]: ").strip()
        if not answer or answer == "0":
            return AUTO, None
        try:
            number = int(answer)
        except ValueError:
            number = -1
        if not 1 <= number <= len(PACKAGES):
            print("Enter one of the numbers above")
            continue
        label, resource = PACKAGES[number - 1]
        if label == CUSTOM:
            break
        path = package_path(resource)
        if os.path.isfile(path):
            return label, path
        print(f"Missing file: {path}")
        if resource.startswith("pkeyconfig_win11"):
            source = "pkeyconfig-csvlk.xrm-ms" if resource.endswith("csvlk") else "pkeyconfig.xrm-ms"
            print(f"Copy {source} from a Windows 11 PC or ISO")
            print(r"(Windows\System32\spp\tokens\pkeyconfig) and save it under that name.")
    while True:
        path = input("Path to .xrm-ms file: ").strip().strip('"')
        if os.path.isfile(path):
            return label, path
        print("File not found")


def package_path(resource):
    return resource if os.path.isabs(resource) else os.path.join(PKEYCONFIG_DIR, resource + ".xrm-ms")


def detect_package(key):
    configurations = {}
    for label, resource in PACKAGES:
        if resource is None:
            continue
        path = package_path(resource)
        if not os.path.isfile(path):
            continue
        identity = os.path.normcase(os.path.realpath(path))
        if identity not in configurations:
            configurations[identity] = (path, [])
        configurations[identity][1].append(label)

    print(f"\nChecking {len(configurations)} available configuration files locally...")
    matches = []
    for path, labels in configurations.values():
        result, pid2, pid4 = run_pidgenx(key, path)
        if result == 0:
            matches.append((" / ".join(labels), path, pid2, pid4))

    if not matches:
        print("No match found in the available configuration files.")
        print("This does not necessarily mean the key is invalid; try a custom PkeyConfig file.")
        return None

    print(f"\nFound {len(matches)} matching configuration(s):")
    for number, (label, path, _, pid4) in enumerate(matches, 1):
        description = describe(path, text_at(pid4, 0x088, 0x118))
        channel = text_at(pid4, 0x478, 0x4F8)
        print(f"{number:3}. {label}")
        print(f"     {description} | Channel: {channel}")

    if len(matches) == 1:
        return matches[0]

    print("Some products share key families; a match may not identify one exact software version.")
    while True:
        answer = input(f"Show details for match [1-{len(matches)}]: ").strip()
        try:
            number = int(answer)
        except ValueError:
            number = 0
        if 1 <= number <= len(matches):
            return matches[number - 1]
        print("Enter one of the match numbers above")


def load_pidgenx():
    # The dll shipped with the original program is 32-bit; a 64-bit Python needs the system one
    system_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pidgenx.dll")
    for path in (os.path.join(HERE, "ProductKeyUtilities.dll"), system_dll):
        try:
            return ctypes.WinDLL(path)
        except OSError:
            continue
    sys.exit("Error: could not load ProductKeyUtilities.dll or pidgenx.dll")


def sized_buffer(size, declared_size):
    buffer = ctypes.create_string_buffer(size)
    buffer[0:2] = declared_size.to_bytes(2, "little")
    return buffer


def run_pidgenx(key, pkeyconfig_path):
    pidgenx = load_pidgenx().PidGenX
    pidgenx.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    pidgenx.restype = ctypes.c_uint32
    pid2 = sized_buffer(100, 50)
    pid3 = sized_buffer(0xA4, 0xA4)
    pid4 = sized_buffer(0x4F8, 0x4F8)
    result = pidgenx(key, pkeyconfig_path, "XXXXX", None, pid2, pid3, pid4)
    return result, pid2.raw, pid4.raw


def text_at(buffer, start, end):
    return buffer[start:end].decode("utf-16-le", "replace").split("\0", 1)[0]


def describe(pkeyconfig_path, activation_id):
    try:
        outer = ET.parse(pkeyconfig_path)
        info_bin = next(node for node in outer.iter() if node.tag.endswith("}infoBin"))
        inner = ET.fromstring(base64.b64decode(info_bin.text))
        wanted = "{" + activation_id.lower() + "}"
        for config in inner.iterfind("pkc:Configurations/pkc:Configuration", PKC_NS):
            if (config.findtext("pkc:ActConfigId", "", PKC_NS) or "").lower() == wanted:
                return (config.findtext("pkc:ProductDescription", "Not Found", PKC_NS) or "").strip()
    except (ET.ParseError, StopIteration, ValueError, OSError):
        pass
    return "Not Found"


def mak_count(extended_pid):
    pid = extended_pid.replace("XXXXX", "55041")
    request_xml = (
        '<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0">'
        "<VersionNumber>2.0</VersionNumber>"
        "<RequestType>2</RequestType>"
        f"<Requests><Request><PID>{pid}</PID></Request></Requests>"
        "</ActivationRequest>"
    )
    request_bytes = request_xml.encode("utf-16-le")
    request_b64 = base64.b64encode(request_bytes).decode()
    digest = base64.b64encode(hmac.new(HMAC_KEY, request_bytes, hashlib.sha256).digest()).decode()
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        "<soap:Body>"
        '<BatchActivate xmlns="http://www.microsoft.com/BatchActivationService">'
        f"<request><Digest>{digest}</Digest><RequestXml>{request_b64}</RequestXml></request>"
        "</BatchActivate>"
        "</soap:Body></soap:Envelope>"
    )
    http_request = urllib.request.Request(
        URL,
        data=envelope.encode("utf-8"),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": "http://www.microsoft.com/BatchActivationService/BatchActivate",
            # urllib's default "Python-urllib/3.x" agent is rejected with 403
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 4.0.30319.42000)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return f"HTTP {error.code} {error.reason}"
    except urllib.error.URLError as error:
        return f"request failed ({error.reason})"

    # <ResponseXml> holds an escaped inner XML document
    match = re.search(r"<ResponseXml>(.*?)</ResponseXml>", body, re.S)
    inner = html.unescape(match.group(1)) if match else body

    def field(name):
        found = re.search(rf"<{name}>(.*?)</{name}>", inner, re.S)
        return found.group(1) if found else None

    remaining = field("ActivationRemaining")
    error_code = field("ErrorCode")
    if remaining is None:
        return "no ActivationRemaining in response"
    if int(remaining) < 0 and error_code == "0x67":
        return "0 (Blocked)"
    if error_code:
        return f"{remaining} (ErrorCode {error_code})"
    return remaining


def main():
    show_banner()
    key = ask_key()
    package, pkeyconfig_path = ask_package()
    started = time.time()

    if pkeyconfig_path is None:
        match = detect_package(key)
        if match is None:
            return
        package, pkeyconfig_path, pid2, pid4 = match
        result = 0
    else:
        result, pid2, pid4 = run_pidgenx(key, pkeyconfig_path)

    print()
    print("Product Key:     " + key)
    print("Package:         " + package)
    if result != 0:
        message = PIDGENX_ERRORS.get(result, "Unsupported PKeyConfig file or Invalid Key")
        print(f"Error:           {message} (0x{result:08X})")
        return

    extended_pid = text_at(pid4, 0x008, 0x088)
    activation_id = text_at(pid4, 0x088, 0x118)
    print("Key Status:      Valid for selected configuration")
    print("Product ID:      " + text_at(pid2, 0, 100))
    print("Extended PID:    " + extended_pid)
    print("Activation ID:   " + activation_id)
    print("Edition Type:    " + text_at(pid4, 0x118, 0x378))
    print("Description:     " + describe(pkeyconfig_path, activation_id))
    print("Edition ID:      " + text_at(pid4, 0x378, 0x3F8))
    print("License Type:    " + text_at(pid4, 0x3F8, 0x478))
    print("License Channel: " + text_at(pid4, 0x478, 0x4F8))
    print("Crypto ID:       " + extended_pid[7:11])
    if input("\nCheck MAK count online? [y/N]: ").strip().lower() in ("y", "yes"):
        print("MAK Count:       " + mak_count(extended_pid))
    print(f"Benchmark:       {time.time() - started:.1f} seconds")


if __name__ == "__main__":
    main()
