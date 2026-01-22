from bs4 import BeautifulSoup
from termcolor import colored
import httpx
import trio

import os
from argparse import ArgumentParser
import csv
from datetime import datetime
import time
import importlib
import pkgutil
import hashlib
import re
import sys
import string
import random
import json

from .localuseragent import ua
from .instruments import TrioProgress


try:
    import cookielib    
except Exception:
    import http.cookiejar as cookielib


DEBUG        = False
EMAIL_FORMAT = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

__version__ = "1.61"


def import_submodules(package, recursive=True):
    """Get all the holehe submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        # Skip hidden or special directories (like __pycache__)
        if name.startswith('_'):
            continue
        full_name = package.__name__ + '.' + name
        try:
            module = importlib.import_module(full_name)
        except Exception:
            # Ignore modules that fail to import (corrupt or non-modules)
            continue
        results[full_name] = module
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results


def get_functions(modules, args=None):
    """Transform the modules objects to functions

    Safely extract callable functions from imported modules. Some package
    entries (packages with submodules like `cms`) won't export a symbol
    with the same name and should be skipped instead of raising.
    """
    websites = []

    for module_name, modu in modules.items():
        # Only consider deeper modules (module path length > 3)
        if len(module_name.split('.')) <= 3:
            continue

        site = module_name.split('.')[-1]

        # Retrieve the expected attribute; skip if missing
        func = modu.__dict__.get(site)
        if func is None:
            # not a leaf module with the expected callable
            continue

        # Only include callables (functions) — skip other objects
        if not callable(func):
            continue

        # If args indicate no password recovery checks, filter out certain modules
        if args is not None and getattr(args, 'nopasswordrecovery', False) is True:
            func_str = str(func)
            if any(x in func_str for x in ("adobe", "mail_ru", "odnoklassniki", "samsung")):
                continue

        websites.append(func)

    return websites



def is_email(email: str) -> bool:
    """Check if the input is a valid email address

    Keyword Arguments:
    email       -- String to be tested

    Return Value:
    Boolean     -- True if string is an email, False otherwise
    """

    return bool(re.fullmatch(EMAIL_FORMAT, email))

def print_result(data,args,email,start_time,websites):
    def print_color(text,color,args):
        if args.nocolor == False:
            return(colored(text,color))
        else:
            return(text)

    description = print_color("[+] Email used","green",args) + "," + print_color(" [-] Email not used", "magenta",args) + "," + print_color(" [x] Rate limit","yellow",args) + "," + print_color(" [!] Error","red",args)
    if args.noclear==False:
        print("\033[H\033[J")
    else:
        print("\n")
    print("*" * (len(email) + 6))
    print("   " + email)
    print("*" * (len(email) + 6))

    for results in data:
        if results["rateLimit"] and args.onlyused == False:
            websiteprint = print_color("[x] " + results["domain"], "yellow",args)
            print(websiteprint)
        elif "error" in results.keys() and results["error"] and args.onlyused == False:
            toprint = ""
            if results["others"] is not None and "Message" in str(results["others"].keys()):
                toprint = " Error message: " + results["others"]["errorMessage"]
            websiteprint = print_color("[!] " + results["domain"] + toprint, "red",args)
            print(websiteprint) 
        elif results["exists"] == False and args.onlyused == False:
            websiteprint = print_color("[-] " + results["domain"], "magenta",args)
            print(websiteprint)
        elif results["exists"] == True:
            toprint = ""
            if results["emailrecovery"] is not None:
                toprint += " " + results["emailrecovery"]
            if results["phoneNumber"] is not None:
                toprint += " / " + results["phoneNumber"]
            if results["others"] is not None and "FullName" in str(results["others"].keys()):
                toprint += " / FullName " + results["others"]["FullName"]
            if results["others"] is not None and "Date, time of the creation" in str(results["others"].keys()):
                toprint += " / Date, time of the creation " + results["others"]["Date, time of the creation"]

            websiteprint = print_color("[+] " + results["domain"] + toprint, "green",args)
            print(websiteprint)

    print("\n" + description)
    print(str(len(websites)) + " websites checked in " +
          str(round(time.time() - start_time, 2)) + " seconds")


def export_csv(data,args,email):
    """Export result to csv"""
    if args.csvoutput == True:
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        name_file="holehe_"+str(round(timestamp))+"_"+email+"_results.csv"
        with open(name_file, 'w', encoding='utf8', newline='') as output_file:
            fc = csv.DictWriter(output_file,fieldnames=data[0].keys())
            fc.writeheader()
            fc.writerows(data)
        exit("All results have been exported to "+name_file)

async def launch_module(module,email, client, out):
    try:
        await module(email, client, out)
    except Exception:
        try:
            name = str(module).split('<function ')[1].split(' ')[0] if '<function ' in str(module) else str(module)
        except Exception:
            name = "unknown"
        out.append({"name": name,"domain": name,
                    "rateLimit": False,
                    "error": True,
                    "exists": False,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})
async def maincore():
    parser= ArgumentParser(description=f"holehe v{__version__}")
    parser.add_argument("email",
                    nargs='+', metavar='EMAIL',
                    help="Target Email")
    parser.add_argument("--only-used", default=False, required=False,action="store_true",dest="onlyused",
                    help="Displays only the sites used by the target email address.")
    parser.add_argument("--no-color", default=False, required=False,action="store_true",dest="nocolor",
                    help="Don't color terminal output")
    parser.add_argument("--no-clear", default=False, required=False,action="store_true",dest="noclear",
                    help="Do not clear the terminal to display the results")
    parser.add_argument("-NP","--no-password-recovery", default=False, required=False,action="store_true",dest="nopasswordrecovery",
                    help="Do not try password recovery on the websites")
    parser.add_argument("-C","--csv", default=False, required=False,action="store_true",dest="csvoutput",
                    help="Create a CSV with the results")
    parser.add_argument("-T","--timeout", type=int , default=10, required=False,dest="timeout",
                    help="Set max timeout value (default 10)")

    args = parser.parse_args()
    credit()
    email=args.email[0]

    if not is_email(email):
        exit("[-] Please enter a target email ! \nExample : holehe email@example.com")

    # Import Modules
    modules = import_submodules("sentinelle.engines.mail.modules")
    websites = get_functions(modules,args)
    # Get timeout
    timeout=args.timeout
    # Start time
    start_time = time.time()
    # Def the async client
    client = httpx.AsyncClient(timeout=timeout)
    # Launching the modules
    out = []
    instrument = TrioProgress(len(websites))
    trio.lowlevel.add_instrument(instrument)
    async with trio.open_nursery() as nursery:
        for website in websites:
            nursery.start_soon(launch_module, website, email, client, out)
    trio.lowlevel.remove_instrument(instrument)
    # Sort by modules names
    out = sorted(out, key=lambda i: i['name'])
    # Close the client
    await client.aclose()
    # Print the result
    print_result(out,args,email,start_time,websites)
    credit()
    # Export results
    export_csv(out,args,email)

def main():
    trio.run(maincore)

from ...core.engine import BaseEngine, EventType

class MailEngine(BaseEngine):
    def __init__(self, console=None):
        super().__init__()
        self.console = console

    async def run(self, email, timeout=30, max_concurrent=20, websites=None, **kwargs):
        # Use provided websites or load them if not provided
        if websites is None:
            modules = import_submodules("sentinelle.engines.mail.modules")
            websites = get_functions(modules, None)
        
        self.log(f"🚀 Initializing scan for {email} ({len(websites)} modules loaded)")

        # Capacity limiter to avoid overwhelming the network/system
        limiter = trio.CapacityLimiter(max_concurrent)

        # Def the async client
        async with httpx.AsyncClient(timeout=timeout) as client:
            out = []
            try:
                async with trio.open_nursery() as nursery:
                    for website in websites:
                        nursery.start_soon(self._wrapped_launch, website, email, client, out, limiter)
            except (Exception, BaseException) as e:
                if isinstance(e, KeyboardInterrupt):
                    raise
                self.error(f"⚠️ Scan partially interrupted: {str(e)}")
            
            # Sort by modules names
            out = sorted(out, key=lambda i: i['name'])
            self.emit(EventType.COMPLETE, data=out)
            return out

    async def _wrapped_launch(self, module, email, client, out, limiter=None):
        name = str(module).split('<function ')[1].split(' ')[0] if '<function ' in str(module) else str(module)
        
        async with (limiter or trio.CapacityLimiter(100)):
            self.log(f"📡 Querying {name}...")
                
            initial_len = len(out)
            try:
                await launch_module(module, email, client, out)
            except Exception as e:
                self.log(f"⚠️ Error in {name}: {str(e)}")
            
            # Extract result
            res = out[-1] if len(out) > initial_len else {"name": name, "domain": name, "exists": False, "error": False, "rateLimit": False}
            
            # Emit data event for UI update
            self.emit(EventType.DATA, data=res)
            
            # Advance progress
            self.progress(advance=1)
                
            if len(out) > initial_len:
                res = out[-1]
                if res.get('exists'):
                    self.log(f"✅ Found on {res['domain']}")
                elif res.get('error'):
                    self.log(f"⚠️ Error on {res['domain']}")
