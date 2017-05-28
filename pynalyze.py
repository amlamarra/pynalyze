#!/usr/bin/env python3
""" pynalyze is a URL analyzer
AUTHOR: Andrew Lamarra
"""
import validators
import argparse


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Checks if a URL is malicious")
    parser.add_argument("URL", nargs="?", help="Provide the URL")
    args = parser.parse_args()

    # Prompt the user for the URL if none were supplied
    if args.URL:
        url = args.URL
    else:
        url = input("Enter a URL to analyze: ")

    if "://" not in url:
        url = "http://" + url
    protocol = url.split("://")[0]
    if protocol != "http" and protocol != "https":
        print("This only accepts either the HTTP or HTTPS protocol")

    # Validate that it IS a URL
    print("\nValidating {}".format(url))
    if validators.url(url):
        print("Valid URL")
    else:
        print("Invalid URL")
