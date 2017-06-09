import requests


def testuri(url):
    """ Uses testuri.org to get the contents of a page.
    ACCEPTS: 1 string (the URL)
    RETURNS:
    """

    payload = {"url": url, "http": "1.1", "agent": "2"}
    r = requests.post("http://testuri.org/sniffer", data=payload)

    if r.status_code != requests.codes.ok:
        print("Something went wrong with the request")
        r.raise_for_status()

    turi_source = r.text.lower().split("\n")

    header = "<h3>http response headers</h3>"
    line = [line for line in turi_source if header in line][0]
    linum = turi_source.index(line) + 1

    status = turi_source[linum].split("<b>status</b>: ")[1]
    status = status.split("<br><b>content-type</b>:")[0]
    status = status.split(" ")[1]

    print("Status code: {}\n".format(status))
