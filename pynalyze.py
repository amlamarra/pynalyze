#!/usr/bin/env python3
""" pynalyze attempts to determine if a URL is malicious or not
AUTHOR: Andrew Lamarra
"""

import os
import time
# import argparse
import sqlite3
import configparser
import validators
from modules import analysis


def set_url():
    """Get the URL to analyze from the user"""
    while True:
        url = input("\nEnter a URL to analyze: ")

        # Add the protocol if not supplied
        if "://" not in url:
            protocol = cfg["Settings"]["DefaultProtocol"].lower()
            url = "{}://{}".format(protocol, url)
        else:
            protocol = url.split("://")[0].lower()

        # Only accept HTTP and HTTPS
        if protocol != "http" and protocol != "https":
            print("This only accepts either the HTTP or HTTPS protocols")
            continue

        # Validate that it IS a URL
        if not validators.url(url):
            print("Invalid URL")
        else:
            break

    # Save the URL
    if cfg["Settings"]["RestoreURL"] == "True":
        cfg["Main"] = {"URL": url}
        with open("settings.ini", "w") as f:
            cfg.write(f)

    return url


def list_keys():
    cur.execute("SELECT * FROM keys")
    data = cur.fetchall()

    max_name_len = len(max([row[0] for row in data if row[0]], key=len))
    max_key_len = len(max([row[1] for row in data if row[1]], key=len))

    print(" +-{}-+-{}-+".format("-"*max_name_len, "-"*max_key_len))
    print(" | Service{} | Key{} |".format(" "*(max_name_len-7), " "*(max_key_len-3)))
    print(" +-{}-+-{}-+".format("-"*max_name_len, "-"*max_key_len))
    for row in data:
        print(" | {} | {} |".format(row[0]+" "*(max_name_len-len(row[0])), row[1]+" "*(max_key_len-len(row[1]))))
    print(" +-{}-+-{}-+".format("-"*max_name_len, "-"*max_key_len))


def menu_apikeys():
    while True:
        print("\nAPI KEYS MENU\n")
        print("1) List current API keys")
        print("2) Add/change/remove a key")
        print("3) Back to main menu")
        print("4) Exit\n")
        ans = input(">>> ")

        if ans == "1":
            print()
            list_keys()
        elif ans.lower() == "back" or ans == "3":
            break
        elif ans.lower() == "exit" or ans == "4":
            raise SystemExit
        else:
            print("\n***INVALID SELECTION***")
            time.sleep(1)
            continue


def menu_settings(url):
    while True:
        rest_url = cfg["Settings"]["RestoreURL"]
        def_proto = cfg["Settings"]["DefaultProtocol"]
        follow_redir = cfg["Settings"]["FollowRedirects"]

        print("\nSETTINGS MENU\n")
        print("1) Restore last saved URL upon starting Pynalyze")
        print("   (currently = {})\n".format(rest_url))
        print("2) Set default protocol when not specified in the URL")
        print("   (currently = {})\n".format(def_proto))
        print("3) Automatically follow redirects when getting the page source")
        print("   Each URL in the redirect will still be displayed to you.")
        print("   (currently = {})\n".format(follow_redir))
        print("4) Back to main menu")
        print("5) Exit\n")
        ans = input(">>> ")

        # Define what the options do
        if ans == "1":
            while True:
                value = input("\nChange value from {} to {}? (Y/n) ".format(
                    rest_url, (rest_url == "False"))).lower()
                if value == "y" or value == "yes" or value == "":
                    cfg["Settings"]["RestoreURL"] = str(rest_url == "False")
                    if cfg["Settings"]["RestoreURL"] == "True" and url:
                        cfg["Main"] = {"URL": url}
                    elif cfg["Settings"]["RestoreURL"] == "False" and url:
                        cfg.remove_section("Main")
                    break
                elif value == "n" or value == "no":
                    break
                else:
                    print("Please enter 'y' (yes) or 'n' (no)")
        elif ans == "2":
            while True:
                print("\n    1) HTTP")
                print("    2) HTTPS")
                value = input("    Select the protocol: ")
                if value == "1":
                    cfg["Settings"]["DefaultProtocol"] = "HTTP"
                    break
                elif value == "2":
                    cfg["Settings"]["DefaultProtocol"] = "HTTPS"
                    break
                else:
                    print("Please enter '1' or '2'")
        elif ans == "3":
            while True:
                value = input("\nChange value from {} to {}? (Y/n) ".format(
                    follow_redir, (follow_redir == "False"))).lower()
                if value == "y" or value == "yes" or value == "":
                    cfg["Settings"]["FollowRedirects"] = str(
                        follow_redir == "False")
                    break
                elif value == "n" or value == "no":
                    break
                else:
                    print("Please enter 'y' (yes) or 'n' (no)")
        elif ans.lower() == "back" or ans == "4":
            break
        elif ans.lower() == "exit" or ans == "5":
            raise SystemExit
        else:
            print("\n***INVALID SELECTION***")
            time.sleep(1)
            continue

        # Save the settings
        with open("settings.ini", "w") as f:
            cfg.write(f)


def menu_analysis(url):
    while True:
        print("\nANALYSIS MENU\n")
        print("   URL to analyze: {}\n".format(url))
        print("1) Get page source")
        print("2) Back to main menu")
        print("3) Exit\n")
        ans = input(">>> ")

        # Define what the options do
        if ans == "1":
            if url == "":
                print("The URL hasn't been set yet")
            else:
                analysis.get_source(url)
        elif ans.lower() == "back" or ans == "2":
            break
        elif ans.lower() == "exit" or ans == "3":
            raise SystemExit
        else:
            print("\n***INVALID SELECTION***")
            time.sleep(1)


def menu_main():
    # Attempt to load the saved URL
    try:
        url = cfg["Main"]["URL"]
    except KeyError:
        url = ""

    while True:
        print("\nMAIN MENU\n")
        print("   URL to analyze: {}\n".format(url))
        print("1) Set/change URL")
        print("2) Analysis")
        print("3) Settings")
        print("4) Manage API Keys")
        print("5) Exit\n")
        ans = input(">>> ")

        # Define what the options do
        if ans == "1":
            url = set_url()
        elif ans == "2" and url == "":
            print("\nYou must first set a URL")
            time.sleep(1)
        elif ans == "2" and url != "":
            menu_analysis(url)
        elif ans == "3":
            menu_settings(url)
        elif ans == "4":
            menu_apikeys()
        elif ans == "5" or ans.lower() == "exit":
            raise SystemExit
        else:
            print("\n***INVALID SELECTION***")
            time.sleep(1)


def is_sqlite3(filename):
    """Check to see if a file is a SQLite database"""
    from os.path import isfile, getsize

    if not isfile(filename):
        return False
    if getsize(filename) < 100:  # SQLite database file header is 100 bytes
        return False

    with open(filename, "rb") as fd:
        header = fd.read(100)

    return header[:16] == b"SQLite format 3\x00"


if __name__ == "__main__":
    # I may use arguments in the future, but not right now
    # parser = argparse.ArgumentParser(description="Analyze a URL")
    # parser.add_argument("URL", nargs="?", help="Provide the URL")
    # args = parser.parse_args()

    # Load saved settings
    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read("settings.ini")

    # Initialize settings if settings.ini doesn't exist
    if not cfg.sections():
        cfg["Settings"] = {"RestoreURL": False,
                           "DefaultProtocol": "HTTP",
                           "FollowRedirects": False}
        with open("settings.ini", "w") as f:
            cfg.write(f)

    # Initialize the API keys database if it doesn't exist
    db_file = "api_keys.db"
    if not is_sqlite3(db_file):
        if os.path.isfile(db_file):
            os.remove(db_file)
        conn = sqlite3.connect(db_file)
        cur = conn.cursor()
        cur.execute("CREATE TABLE keys (service text, key text)")
    else:
        conn = sqlite3.connect(db_file)
        cur = conn.cursor()
    conn.commit()

    menu_main()
