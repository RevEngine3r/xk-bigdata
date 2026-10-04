"""
Each formatter takes a raw proxy line (e.g. "1.2.3.4:8080") and returns
the converted string. Add your own by defining a function and registering it.
"""

FORMATTERS = {}


def register(name):
    def deco(fn):
        FORMATTERS[name] = fn
        return fn

    return deco


@register("https")
def fmt_https(line):
    return f"https://{line}?insecure=1"
