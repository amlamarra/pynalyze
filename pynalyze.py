#!/usr/bin/env python3
""" pynalyze attempts to determine if a URL is malicious or not
AUTHOR: Andrew Lamarra
"""

import os
import argparse
import validators
from modules import analysis


URL = [""]


def set_url():
    while True:
        URL[0] = input("Enter a URL to analyze: ")

        # Add the protocol if not supplied
        if "://" not in URL[0]:
            URL[0] = "http://" + URL[0]
            protocol = "http"
        else:
            protocol = URL[0].split("://")[0]

        # Only accept HTTP and HTTPS
        if protocol != "http" and protocol != "https":
            print("This only accepts either the HTTP or HTTPS protocol\n")
        else:
            break

    # Validate that it IS a URL
    if validate(URL[0]):
        print("Good URL\n")
    else:
        print("Bad URL\n")
        raise SystemExit


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


def menu_preferences():
    while True:
        print("PREFERENCES MENU\n")
        print("1) Restore last saved URL upon starting Pynalyze")
        print("   (currently = False)")
        print("2) Set default URL protocol when not specified")
        print("   (currently = HTTP)")
        print("3) Automatically follow redirects when getting the page source")
        print("   Each URL in the redirect will still be displayed to you.")
        print("   (currently = False)")
        print("4) Back to main menu")
        print("5) Exit\n")
        ans = input(">>> ")
        print()

        if ans.lower() == "back" or ans == "4":
            break
        elif ans.lower() == "exit" or ans == "5":
            raise SystemExit
        else:
            print("Invalid Selection\n")


def menu_analysis():
    while True:
        print("ANALYSIS MENU\n")
        print("   URL to analyze: {}\n".format(URL[0]))
        print("1) Get page source")
        print("2) Back to main menu")
        print("3) Exit\n")
        ans = input(">>> ")
        print()

        if ans == "1":
            if URL[0] == "":
                print("The URL hasn't been set yet")
            else:
                analysis.testuri(URL[0])
        elif ans.lower() == "back" or ans == "2":
            break
        elif ans.lower() == "exit" or ans == "3":
            raise SystemExit
        else:
            print("Invalid selection\n")


def menu_main():
    while True:
        print("MAIN MENU\n")
        print("   URL to analyze: {}\n".format(URL[0]))
        print("1) Set/change URL")
        print("2) Analysis")
        print("3) Preferences")
        print("4) Manage API Keys")
        print("5) Exit\n")
        ans = input(">>> ")
        print()

        if ans == "exit" or ans == "5":
            raise SystemExit
        elif ans == "1":
            set_url()
        elif ans == "2":
            menu_analysis()
        else:
            print("Invalid selection\n")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Checks if a URL is malicious")
    parser.add_argument("URL", nargs="?", help="Provide the URL")
    args = parser.parse_args()

    # Save the URL if one was supplied
    if args.URL:
        URL[0] = args.URL
    else:
        URL[0] = ""

    # Load saved preferences
    try:
        with open(os.environ['HOME']+"/.pynalyze", "r") as f:
            content = f.read()
    except FileNotFoundError:
        print("No preferences file found. Using defaults.")

    menu_main()
