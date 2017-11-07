#!/usr/bin/env python3
""" pynalyze attempts to determine if a URL is malicious or not
AUTHOR: Andrew Lamarra
"""

import os
import sqlite3
# import argparse
import configparser
import validators
from modules import analysis


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def set_url():
    """Get the URL to analyze from the user"""
    while True:
        url = input("\nEnter a URL to analyze: ")

        # Allow the user to set an empty URL for some reason
        if url == "":
            break

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

    os.system("cls" if os.name == "nt" else "clear")

    return url


def list_keys():
    # Query the database & save the results
    cur.execute("SELECT * FROM keys")
    data = cur.fetchall()

    # Get the string length of the longest key name & key
    max_name_len = len(max([row[1] for row in data], key=len))
    max_key_len = len(max([row[2] for row in data], key=len))

    # These lengths shouldn't be less than 7 & 3 for the header row names
    if max_name_len < 4:
        max_name_len = 4
    if max_key_len < 3:
        max_key_len = 3

    # Print it all out in a nicely formatted table
    print("\n +-{}-+-{}-+".format("-"*(max_name_len+3), "-"*max_key_len))
    name_buff = " " * (max_name_len - 4)
    key_buff = " " * (max_key_len - 3)
    print(" | Service{} | Key{} |".format(name_buff, key_buff))
    print(" +-{}-+-{}-+".format("-"*(max_name_len+3), "-"*max_key_len))
    for i, row in enumerate(data):
        name = row[1] + " " * (max_name_len - len(row[1]))
        key = row[2] + " " * (max_key_len - len(row[2]))
        print(" | {}. {} | {} |".format(data[i][0], name, key))
    print(" +-{}-+-{}-+".format("-"*(max_name_len+3), "-"*max_key_len))


def change_keys():
    cur.execute("SELECT COUNT(*) FROM keys")
    rows = cur.fetchall()[0][0]
    if rows > 1:
        num = input("Which one? (1-{}, c to cancel) ".format(rows))
    else:
        num = input("Which one? (1, c to cancel) ".format(rows))
    while not num.isdigit() or int(num) < 1 or int(num) > rows:
        if num == "c":
            break
        num = input("Please enter a number from 1 to {} (c to cancel): ".format(rows))
    else:
        key = input("\nEnter the key (leave blank to remove it): ")
        cur.execute("UPDATE keys SET key=? WHERE id=?", (key, num))
        conn.commit()


def menu_apikeys():
    error = ""
    while True:
        print("\nAPI KEYS MENU")
        print("=============\n")
        print("1) List current API keys")
        print("2) Add/change/remove a key")
        print("3) Back to main menu")
        print("4) Exit\n")
        print(error)
        error = ""
        ans = input(">>> ")

        if ans == "1":
            os.system("cls" if os.name == "nt" else "clear")
            list_keys()
        elif ans == "2":
            change_keys()
            os.system("cls" if os.name == "nt" else "clear")
            list_keys()
        elif ans == "3" or ans.lower() == "back":
            os.system("cls" if os.name == "nt" else "clear")
            break
        elif ans == "4" or ans.lower() == "exit":
            raise SystemExit
        else:
            error = "***INVALID SELECTION***"
            os.system("cls" if os.name == "nt" else "clear")


def menu_settings():
    # Attempt to load the saved URL
    try:
        url = cfg["Main"]["URL"]
    except KeyError:
        url = ""

    error = ""
    while True:
        rest_url = cfg["Settings"]["RestoreURL"]
        def_proto = cfg["Settings"]["DefaultProtocol"]
        follow_redir = cfg["Settings"]["FollowRedirects"]

        print("\nSETTINGS MENU")
        print("=============\n")
        print("1) Restore last saved URL upon starting Pynalyze")
        print("   (currently = {})\n".format(rest_url))
        print("2) Set default protocol when not specified in the URL")
        print("   (currently = {})\n".format(def_proto))
        print("3) Automatically follow redirects when getting the page source")
        print("   Each URL in the redirect chain will still be displayed to you")
        print("   (currently = {})\n".format(follow_redir))
        print("4) Back to main menu")
        print("5) Exit\n")
        print(error)
        error = ""
        ans = input(">>> ")
        clear()

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
            clear()
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
            clear()
        elif ans == "3":
            while True:
                value = input("\nChange value from {} to {}? (Y/n) ".format(
                    follow_redir, (follow_redir == "False"))).lower()
                if value == "y" or value == "yes" or value == "":
                    cfg["Settings"]["FollowRedirects"] = str(follow_redir == "False")
                    break
                elif value == "n" or value == "no":
                    break
                else:
                    print("Please enter 'y' (yes) or 'n' (no)")
            clear()
        elif ans.lower() == "back" or ans == "4":
            clear()
            break
        elif ans.lower() == "exit" or ans == "5":
            raise SystemExit
        else:
            error = "***INVALID SELECTION***"
            continue

        # Save the settings
        with open("settings.ini", "w") as f:
            cfg.write(f)


def menu_analysis():
    # Attempt to load the saved URL
    try:
        url = cfg["Main"]["URL"]
    except KeyError:
        url = ""

    scan_id = ""
    error = ""
    while True:
        print("\nANALYSIS MENU")
        print("=============\n")
        print("   URL to analyze: {}\n".format(url))
        print("1) Set/change URL")
        if url:
            print("2) Get page source")
            print("3) Submit URL to VirusTotal")
            print("4) Retrieve VirusTotal report")
            print("5) Get IP location info")
            print("6) Back to main menu")
            print("7) Exit\n")
        else:
            print("2) Back to main menu")
            print("3) Exit\n")

        print(error)
        error = ""
        ans = input(">>> ")

        # Define what the options do
        if ans == "1":
            url = set_url()
            scan_id = ""
            clear()
        elif ans == "2":
            if url:
                clear()
                analysis.get_source(url, cfg)
            else:
                clear()
                break
        elif ans == "3":
            if url:
                clear()
                scan_id = analysis.virustotal_submit(url, cur)
            else:
                raise SystemExit
        elif ans == "4" and url:
            if scan_id:
                clear()
                analysis.virustotal_retrieve(cur, scan_id)
            else:
                error = "You need to submit the URL to VirusTotal first"
                clear()
        elif ans == "5" and url:
            clear()
            analysis.ipinfo(url, cur)
        elif ans.lower() == "back" or ans == "6" and url:
            clear()
            break
        elif ans.lower() == "exit" or ans == "7" and url:
            raise SystemExit
        else:
            error = "***INVALID SELECTION***"
            clear()


def menu_main():
    error = ""
    while True:
        print("\nMAIN MENU")
        print("=========\n")
        print("1) URL Analysis")
        print("2) Settings")
        print("3) Manage API Keys")
        print("4) Exit\n")
        print(error)
        error = ""
        ans = input(">>> ")

        # Define what the options do
        if ans == "1":
            os.system("cls" if os.name == "nt" else "clear")
            menu_analysis()
        elif ans == "2":
            os.system("cls" if os.name == "nt" else "clear")
            menu_settings()
        elif ans == "3":
            os.system("cls" if os.name == "nt" else "clear")
            menu_apikeys()
        elif ans == "4" or ans.lower() == "exit":
            raise SystemExit
        else:
            error = "***INVALID SELECTION***"
            os.system("cls" if os.name == "nt" else "clear")


def is_sqlite3(filename):
    """ Check to see if a file is a SQLite database.
    ACCEPTS: 1 string (the file name)
    RETURNS: Boolean value """

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

    # First, clear the screen
    os.system("cls" if os.name == "nt" else "clear")

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
        cur.execute("CREATE TABLE keys (id integer PRIMARY KEY, service text, key text)")
        cur.execute("INSERT INTO keys VALUES (1, 'VirusTotal', '')")
        cur.execute("INSERT INTO keys VALUES (2, 'IPinfoDB', '')")
    else:
        conn = sqlite3.connect(db_file)
        cur = conn.cursor()
    conn.commit()

    menu_main()

    # Features to implement...
    # Main Menu:
    #   Generate report from output thus far
    # Settings:
    #   Use the latest VirusTotal report if newer than X days (default 10)
    #   Save history to a file (default False)
    # Analysis:
    #   Save page source to a file
    #   Analyze multiple URLs at once
    # API Keys:
    #   Encrypt database file
