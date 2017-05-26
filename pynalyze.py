#!/usr/bin/env python3
""" pynalyze is a URL analyzer
AUTHOR: Andrew Lamarra
"""
import validators


# Prompt the user for the URL
url = input("Enter a URL to analyze: ")

# Validate that it IS a URL... This will be difficult
print(validators.url(url))
