import requests


def testuri(url):
    """ Uses testuri.org to get the contents of a page.
    ACCEPTS: 1 string (the URL)
    RETURNS:
    """

    payload = {"url": url, "http": "1.1", "agent": "2"}
    r = requests.post("http://testuri.org/sniffer", data=payload)

    if r.status_code == requests.codes.ok:
        print(r.text + "\n")
    else:
        print("Something went wrong with the request")
        r.raise_for_status()
