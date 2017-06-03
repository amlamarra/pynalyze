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

    turi_source = r.text.split("\n")
    print()
    # code = turi_source.find("<h3>HTTP Response Headers</h3>")
    header = "<H3>HTTP Response Headers</H3>"
    # print([line for i, line in enumerate(turi_source) if header in line])
    for i, line in enumerate(turi_source):
        if header.lower() in line.lower():
            print(line)
            print(i)
            linum = i

    status = turi_source[linum+1].split("<b>Status</b>: ")[1]
    status = status.split("<br><b>Content-Type</b>:")[0]
    status = status.split(" ")[1]

    print("Status code: {}".format(status))
