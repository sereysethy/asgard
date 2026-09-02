import re

def check_options(text):
    """
    Check for short and long options. An option has to be preceeded by "-" for a short option
    or "--" for a long option.
    """
    # check for short option
    if len(text) >= 2 and text[0] == "-" and text[1] != "-" and text[1:].isalnum():
        return True
    elif len(text) >= 2 and text[0] == "+" and text[1:].isalnum():
        return True
    # check for long option
    elif len(text) > 2 and text[0:2] == "--" and text[2:].isalnum():
        return True
    elif len(text) > 2 and text[0:2] == "--" and text[2].isalnum():
        return True
    # check for long option with = and value, --op=value1
    elif re.match(r"^--[\w]+=[\w]+", text):
        return True
    elif text == "-?":
        # command ping
        return True
    elif text == "-":
        # command su -
        return True
    elif text == "-O-" or text == "-P/tmp" or text == "-qO-":
        # command wget: -O-
        return True

    return False