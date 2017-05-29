#!/usr/bin/env python3
""" pynalyze is a URL analyzer
AUTHOR: Andrew Lamarra
"""

import validators
import argparse


def validate(url):
    """ Ensures that the provided URL is a valid URL
    ACCEPTS: 1 string (the URL)
    RETURNS: 1 boolean value
    """

    print("\nValidating {}".format(url))
    if validators.url(url):
        return True
    else:
        return False


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Checks if a URL is malicious")
    parser.add_argument("URL", nargs="?", help="Provide the URL")
    args = parser.parse_args()

    # Prompt the user for the URL if one was not supplied
    if args.URL:
        url = args.URL
    else:
        url = input("Enter a URL to analyze: ")

    # Add the protocol if not supplied
    if "://" not in url:
        url = "http://" + url
        protocol = "http"
    else:
        protocol = url.split("://")[0]

    # Only accept HTTP and HTTPS
    if protocol != "http" and protocol != "https":
        print("This only accepts either the HTTP or HTTPS protocol")
        # Exit program

    # Validate that it IS a URL
    if validate(url):
        print("Good URL")
    else:
        print("Bad URL")
