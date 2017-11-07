import os
import html
import socket
import pprint
import time
import requests

vt_url = "https://www.virustotal.com/vtapi/v2/url/"


def menu_source(source):
    error = ""
    while True:
        print("\nPAGE SOURCE")
        print("===========\n")
        print("1) Save page source to a file")
        print("2) Display page source to screen")
        print("3) Cancel")
        print("4) Exit\n")
        print(error)
        error = ""
        ans = input(">>> ")

        if ans == "1":
            os.system("cls" if os.name == "nt" else "clear")
            fname = input("Enter the file name: ")
            with open(fname, "w") as f:
                f.write(source)
            print("Page source written to: {}/{}".format(os.getcwd(), fname))
            break
        elif ans == "2":
            print("############################## BEGIN PAGE SOURCE ##############################")
            print("\n" + source)
            print("############################### END PAGE SOURCE ###############################")
            break
        elif ans == "3":
            os.system("cls" if os.name == "nt" else "clear")
            break
        elif ans == "4":
            raise SystemExit
        else:
            error = "***INVALID SELECTION***"
            os.system("cls" if os.name == "nt" else "clear")


def get_source(url, cfg):
    """ Uses testuri.org to get the contents of a page.
    ACCEPTS: 1 string (the URL); 1 dict (from configparser with saved settings)
    RETURNS: Nothing """

    # Set the necessary HTTP headers & send the request to testuri.org
    payload = {"url": url, "http": "1.1", "agent": "2"}
    try:
        r = requests.post("http://testuri.org/", data=payload)
    except requests.HTTPError:
        print("Sorry, but the TestURI.org service seems to be unavailable right now.")
        return

    # Exit the function if something went wrong
    if r.status_code != requests.codes.ok:
        print("\nSomething went wrong with the request\n")
        r.raise_for_status()
        return

    # Save the page source to a variable
    turi_src = r.text.split("\n")

    # Extract the status code
    header = "\t<H3>HTTP Response Headers</H3>"
    for line in turi_src:
        if header == line:
            status = line
            break
    else:
        print("Nothing could be found at that URL")
        return

    # line = [line for line in turi_src if header in line][0]
    linum = turi_src.index(status) + 1
    status = turi_src[linum].lower().split("http/1.1 ")[1]
    status = status.split("<br><b>")[0].title()
    status_code = status.split(" ")[0]

    # If this is a redirect, do more stuff
    if "30" in status_code:
        # Get the redirect URL
        redirect = turi_src[linum].split("</a><BR><B>")[0]
        redirect = redirect.split("'>")[1]
        print("This URL redirects to: {}\n".format(redirect))
        if cfg["Settings"]["FollowRedirects"] == "True":
            print("Follow Redirects is set to TRUE. Getting new page source...")
            get_source(redirect, cfg)
            return
        else:
            print("Follow Redirects is set to FALSE.")

    # Extract the page source
    source = r.text.split("<textarea>")[1]
    source = source.split("</textarea>")[0]
    source = html.unescape(source)
    # print(source)
    menu_source(source)


def virustotal_submit(url, cur):
    """ Submits a URL to VirusTotal for scanning
    ACCEPTS: 1 string (the URL); 1 cursor object (to call the database)
    RETURNS: 1 string (the VT unique scan ID) """

    print("Submitting {}\n".format(url))

    # Get the API key from the database
    cur.execute("SELECT key FROM keys WHERE service='VirusTotal'")
    key = cur.fetchall()[0][0]
    if not key:  # Exit if no key is saved
        print("No API key for VirusTotal...\n")
        return

    # Set the necessary HTTP headers & send the request to VT
    params = {"apikey": key, "url": url}
    r = requests.post(vt_url+"scan", data=params)

    # Save the response (json format) and display
    json = r.json()
    print(json["verbose_msg"])
    print("Scan date: {}".format(json["scan_date"]))
    # print("Response code: {}".format(json["response_code"]))

    return json["scan_id"]


def virustotal_retrieve(cur, scan_id):
    """ Retrieves the scan report from VirusTotal
    ACCEPTS: 1 cursor object (to call the database); 1 string (the scan ID given by VT)
    RETURNS: Nothing """

    # Get the API key from the database
    cur.execute("SELECT key FROM keys WHERE service='VirusTotal'")
    key = cur.fetchall()[0][0]

    # Set the necessary HTTP headers & send the request to VT
    params = {"apikey": key, "resource": scan_id}
    r = requests.post(vt_url+"report", data=params)

    # Save the response (json format) and display
    json = r.json()
    print(json["verbose_msg"])
    print("Response code: {}".format(json["response_code"]))
    print("VirusTotal found {} positive result(s) out of {} scans".format(
        json["positives"], json["total"]))

    for scanner in json["scans"]:
        if json["scans"][scanner]["detected"]:
            print("\t{}: {}".format(scanner, json["scans"][scanner]["result"]))


def ipinfo(url, cur):
    """ Gets the location of an IP address from IPinfoDB.com
    ACCEPTS: 1 string (the URL); 1 cursor object (to call the database)
    RETURNS: Nothing """

    # Get the API key from the database
    cur.execute("SELECT key FROM keys WHERE service='IPinfoDB'")
    key = cur.fetchall()[0][0]
    if not key:  # Exit if no key is saved
        print("No API key for IPinfoDB...\n")
        return

    # Start building the necessary HTTP Headers
    params = {"key": key, "format": "json"}

    # Extract the domain from the URL
    domain = url.split("/")[2]
    try:
        # Get the IP address from the domain & save as a header
        params["ip"] = socket.gethostbyname(domain)
    except socket.gaierror:
        # If domain is not found...
        print("\nNo IP address found for that domain")
        time.sleep(1.5)
        return

    # Send the request to IPinfoDB
    info_url = "https://api.ipinfodb.com/v3/ip-city"
    r = requests.get(info_url, params=params)

    # Save the response (json format) and display
    json = r.json()
    print("City Name:   {}".format(json["cityName"]))
    print("Region Name: {}".format(json["regionName"]))
    print("Zip Code:    {}".format(json["zipCode"]))
    print("Time Zone:   {}".format(json["timeZone"]))
    print("Country:     {}".format(json["countryName"]))
    print("IP address:  {}".format(json["ipAddress"]))


# Just saving this in case I need it later
HTML_CODES = {
    "200": "OK",
    "300": "Multiple Choices",
    "301": "Moved Permanently",
    "302": "Found",
    "304": "Not Modified",
    "307": "Temporary Redirect",
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "410": "Gone",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "503": "Service Unavailable",
    "550": "Permission Denied"}
