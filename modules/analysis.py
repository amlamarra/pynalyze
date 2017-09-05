import html
import socket
import pprint
import time
import requests

vt_url = "https://www.virustotal.com/vtapi/v2/url/"


def get_source(url, cfg):
    """ Uses testuri.org to get the contents of a page.
    ACCEPTS: 1 string (the URL)
    RETURNS:
    """

    payload = {"url": url, "http": "1.1", "agent": "2"}
    r = requests.post("http://testuri.org/sniffer", data=payload)

    if r.status_code != requests.codes.ok:
        print("\nSomething went wrong with the request\n")
        r.raise_for_status()
        return

    turi_src = r.text.split("\n")

    # Extract the status code
    header = "<h3>http response headers</h3>"
    line = [line for line in turi_src if header in line.lower()][0]
    linum = turi_src.index(line) + 1
    status = turi_src[linum].lower().split("<b>status</b>: ")[1]
    status = status.split("<br><b>content-type</b>:")[0]
    status = status.split(" ")[1]
    print("Status code: {}\n".format(status))

    if "30" in status:
        # Get the redirect URL
        redirect = turi_src[linum].split("</a><BR><B>")[0]
        redirect = redirect.split("'>")[1]
        print("Redirect URL: {}\n".format(redirect))
        if cfg["Settings"]["FollowRedirects"] == "True":
            print("Follow Redirects is set to TRUE")

    # Extract the page source
    source = r.text.split("<textarea>")[1]
    source = source.split("</textarea>")[0]
    source = html.unescape(source)
    print(source)


def virustotal_submit(url, cur):
    """ Submits a URL to VirusTotal for scanning """

    print("Submitting {}\n".format(url))
    cur.execute("SELECT key FROM keys WHERE service='VirusTotal'")
    key = cur.fetchall()[0][0]
    if not key:
        print("No VirusTotal API key...\n")
        return

    params = {"apikey": key, "url": url}
    r = requests.post(vt_url+"scan", data=params)
    json = r.json()
    print(json["verbose_msg"])
    print("Scan date: {}".format(json["scan_date"]))
    print("Response code: {}".format(json["response_code"]))

    return json["scan_id"]


def virustotal_retrieve(cur, scan_id):
    """ Retrieves the scan report from VirusTotal """

    cur.execute("SELECT key FROM keys WHERE service='VirusTotal'")
    key = cur.fetchall()[0][0]
    params = {"apikey": key, "resource": scan_id}
    r = requests.post(vt_url+"report", data=params)
    json = r.json()
    print(json["verbose_msg"])
    print("Response code: {}".format(json["response_code"]))
    print("VirusTotal found {} positive result(s) out of {} scans".format(
        json["positives"], json["total"]))

    for scanner in json["scans"]:
        if json["scans"][scanner]["detected"]:
            print("\t{}: {}".format(scanner, json["scans"][scanner]["result"]))


def ipinfo(url, cur):
    """ Gets the location of an IP address from IPinfoDB.com """

    cur.execute("SELECT key FROM keys WHERE service='IPinfoDB'")
    key = cur.fetchall()[0][0]
    if not key:
        print("No IPinfoDB key...\n")
        return

    params = {"key": key, "format": "json"}

    domain = url.split("/")[2]
    try:
        # Get the IP address from the domain
        params["ip"] = socket.gethostbyname(domain)
    except socket.gaierror:
        # If domain is not found...
        print("\nNo IP address found for that domain")
        time.sleep(1.5)
        return

    info_url = "https://api.ipinfodb.com/v3/ip-city"
    r = requests.get(info_url, params=params)
    json = r.json()

    pprint.pprint(json)
