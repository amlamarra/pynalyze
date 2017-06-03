#!/usr/bin/env python3
""" pynalyze is a URL analyzer
AUTHOR: Andrew Lamarra
"""

import sys
import argparse
import validators
from modules import analysis


URL = [""]


def menu():
    print("MAIN MENU\n")
    print("   URL to analyze: {}\n".format(URL[0]))
    print("1) Set/change URL")
    print("2) Preferences")
    print("3) Manage API Keys")
    print("4) Analysis")
    print("5) Exit\n")
    return input(">>> ")


def menu_analysis():
    print("  ANALYSIS MENU\n")
    print("     URL to analyze: {}\n".format(URL[0]))
    print("  1) Get page source")
    print("  2) Back to main menu\n")
    return input(">>> ")


def set_url():
    URL[0] = input("Enter a URL to analyze: ")

    # Add the protocol if not supplied
    if "://" not in URL[0]:
        URL[0] = "http://" + URL[0]
        protocol = "http"
    else:
        protocol = URL[0].split("://")[0]

    # Only accept HTTP and HTTPS
    if protocol != "http" and protocol != "https":
        print("This only accepts either the HTTP or HTTPS protocol")
        sys.exit()

    # Validate that it IS a URL
    if validate(URL[0]):
        print("Good URL\n")
    else:
        print("Bad URL\n")
        sys.exit()


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

    # Save the URL if one was supplied
    if args.URL:
        url = args.URL
    else:
        url = ""

    while True:
        choice = menu()
        print()
        if choice == "exit" or choice == "5":
            # sys.exit()
            break
        elif choice == "1":
            url = set_url()
        elif choice == "4":
            while True:
                choice2 = menu_analysis()
                if choice2 == "1":
                    analysis.testuri(url)
                elif choice2 == "back" or choice2 == "2":
                    break
        else:
            print("Invalid selection\n")
