import html
import requests


def get_source(url):
    """ Uses testuri.org to get the contents of a page.
    ACCEPTS: 1 string (the URL)
    RETURNS:
    """

    payload = {"url": url, "http": "1.1", "agent": "2"}
    r = requests.post("http://testuri.org/sniffer", data=payload)

    if r.status_code != requests.codes.ok:
        print("Something went wrong with the request")
        r.raise_for_status()
        return

    turi_src = r.text.lower().split("\n")

    # Extract the status code
    header = "<h3>http response headers</h3>"
    line = [line for line in turi_src if header in line][0]
    linum = turi_src.index(line) + 1
    status = turi_src[linum].split("<b>status</b>: ")[1]
    status = status.split("<br><b>content-type</b>:")[0]
    status = status.split(" ")[1]
    print("Status code: {}\n".format(status))

    # Extract the page source
    source = r.text.split("<textarea>")[1]
    source = source.split("</textarea>")[0]
    source = html.unescape(source)
    print(source)
