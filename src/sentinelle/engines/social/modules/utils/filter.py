import re
import sys


def filterFoundAccounts(site):
    if "status" in site and site["status"] == "FOUND":
        return True
    else:
        return False


def parseFilter(filter):
    pattern = r"(\w+)([=~><!]+)([^ ]+)\s*(and|or)?\s*"
    matches = re.findall(pattern, filter)

    conditions = []
    logical_ops = []

    for match in matches:
        conditions.append((match[0], match[1], match[2]))
        if match[3]:
            logical_ops.append(match[3])

    return conditions, logical_ops


def evaluate_condition(prop, operator, value, site):
    prop = prop.lower()
    value = value.lower()
    if prop not in site:
        return False

    site_value = str(site[prop])
    site_value = site_value.lower()

    if operator == "=":
        return site_value == value
    elif operator == "~":
        return value in site_value
    elif operator == ">":
        return float(site_value) > float(value)
    elif operator == "<":
        return float(site_value) < float(value)
    elif operator == ">=":
        return float(site_value) >= float(value)
    elif operator == "<=":
        return float(site_value) <= float(value)
    elif operator == "!=":
        return site_value != value
    else:
        return False


def filterAccounts(filter, site):
    conditions, logical_ops = parseFilter(filter)
    result = evaluate_condition(*conditions[0], site)

    if not conditions:
        print(
            '⭕ Filter is not in correct format. Format should be --filter "property=value"'
        )
        sys.exit()
    # Evaluate remaining conditions and combine using logical operators
    for i in range(1, len(conditions)):
        next_result = evaluate_condition(*conditions[i], site)

        if logical_ops[i - 1] == "and":
            result = result and next_result
        elif logical_ops[i - 1] == "or":
            result = result or next_result

    return result


def filterNSFW(site):
    if site["cat"] == "xx NSFW xx":
        return False
    else:
        return True


def applyFilters(sitesToSearch, config):
    # Be defensive: the config module may not yet have runtime attributes
    cfg_filter = getattr(config, 'filter', None)
    if cfg_filter:
        sitesToSearch = list(
            filter(lambda x: filterAccounts(cfg_filter, x), sitesToSearch)
        )
        if (len(sitesToSearch)) <= 0:
            if hasattr(config, 'console') and config.console:
                config.console.print(f"⭕ No sites found for the given filter {cfg_filter}")
            else:
                print(f"⭕ No sites found for the given filter {cfg_filter}")
            sys.exit()
        else:
            if hasattr(config, 'console') and config.console:
                config.console.print(f':page_with_curl: Applied [green1]"{cfg_filter}"[/green1] filter to sites [{len(sitesToSearch)}]')
            else:
                print(f'Applied filter "{cfg_filter}" to sites [{len(sitesToSearch)}]')

    cfg_no_nsfw = getattr(config, 'no_nsfw', False)
    if cfg_no_nsfw:
        sitesToSearch = list(filter(lambda x: filterNSFW(x), sitesToSearch))
        if (len(sitesToSearch)) <= 0:
            if hasattr(config, 'console') and config.console:
                config.console.print(f"⭕ No remaining sites to be searched after NSFW filtering")
            else:
                print("⭕ No remaining sites to be searched after NSFW filtering")
            sys.exit()
        else:
            if hasattr(config, 'console') and config.console:
                config.console.print(f":page_with_curl: Filtered NSFW sites [{len(sitesToSearch)}]")
            else:
                print(f"Filtered NSFW sites [{len(sitesToSearch)}]")

    return sitesToSearch
