import requests
import sys
import os
import chardet
import logging

logger = logging.getLogger(__name__)

from .userAgent import getRandomUserAgent
from ..utils.log import logError

requests.packages.urllib3.disable_warnings()


# Perform a Sync Request and return response details
def do_sync_request(method, url, config, data=None, customHeaders=None, cookies=None):
    # Ensure we have a User-Agent without relying on config.userAgent always existing
    user_agent = getattr(config, "userAgent", None)
    if not user_agent:
        user_agent = getRandomUserAgent(config)
        try:
            config.userAgent = user_agent
        except Exception:
            # If config is a module that doesn't allow assignment, ignore
            pass

    headers = {"User-Agent": user_agent}
    if customHeaders:
        headers.update(customHeaders)
    # Only set proxies parameter if actually needed to avoid performance overhead
    timeout = getattr(config, "timeout", 30)
    request_kwargs = {
        "method": method,
        "url": url,
        "timeout": timeout,
        "verify": False,
        "headers": headers,
        "data": data,
        "cookies": cookies,
    }
    
    # Only add proxies parameter if a proxy is actually configured
    proxy = getattr(config, "proxy", None)
    if proxy:
        request_kwargs["proxies"] = {"http": proxy, "https": proxy}
    try:
        response = requests.request(**request_kwargs)
        if getattr(config, "verbose", False):
            console = getattr(config, "console", None)
            if console:
                console.print(
                    f"  🆗 Sync HTTP Request completed [{method} - {response.status_code}] {url}"
                )
            else:
                print(f"  🆗 Sync HTTP Request completed [{method} - {response.status_code}] {url}")
        return response
    except Exception as e:
        if getattr(config, "verbose", False):
            console = getattr(config, "console", None)
            if console:
                console.print(f"  ❌ Error in Sync HTTP Request [{method}] {url}")
            else:
                print(f"  ❌ Error in Sync HTTP Request [{method}] {url}")
        logError(e, f"Error in Sync HTTP Request [{method}] {url}", config)
        return None


# Perform an Async Request and return response details
async def do_async_request(method, url, session, config, data=None, customHeaders=None):
    # Ensure we have a User-Agent without relying on config.userAgent always existing
    user_agent = getattr(config, "userAgent", None)
    if not user_agent:
        user_agent = getRandomUserAgent(config)
        try:
            config.userAgent = user_agent
        except Exception:
            pass

    headers = {"User-Agent": user_agent}
    if customHeaders:
        headers.update(customHeaders)
    proxy = config.proxy if config.proxy else None

    # If session is closed, bail out early to avoid noisy errors
    if session is None or getattr(session, "closed", False):
        return None

    try:
        response = await session.request(
            method,
            url,
            proxy=proxy,
            timeout=config.timeout,
            allow_redirects=True,
            ssl=False,
            data=data,
            headers=headers,
            max_redirects=10,
        )

        json = None
        try:
            content = await response.text()
        except:
            binaryContent = await response.read()
            encode = chardet.detect(binaryContent)["encoding"]
            content = binaryContent.decode(encode)

        if "Content-Type" in response.headers:
            if "application/json" in response.headers["Content-Type"]:
                json = await response.json()

        responseData = {
            "url": url,
            "status_code": response.status,
            "headers": response.headers,
            "content": content,
            "json": json,
        }

        if getattr(config, "verbose", False) and getattr(config, "console", None):
            config.console.print(
                f"  🆗 Async HTTP Request completed [{method} - {response.status}] {url}"
            )
        return responseData
    except Exception as e:
        # Handle common network/resolver errors with concise logs to avoid flooding
        try:
            from aiohttp import client_exceptions
        except Exception:
            client_exceptions = None

        short_msg = str(e)

        # Specific symptom seen in some environments where resolver is None
        if "getaddrinfo" in short_msg and "NoneType" in short_msg:
            logger.error(f"Resolver error for {url}: {short_msg}")
            logError(e, f"Resolver error for {url}", config)
            return None

        if client_exceptions and isinstance(e, client_exceptions.ClientConnectorDNSError):
            logger.warning(f"DNS error for {url}: {short_msg}")
        else:
            logger.error(f"Error in Async HTTP Request [{method}] {url} | {short_msg}")

        # Log a concise error message (avoid full stacktrace unless verbose)
        logError(e, f"Error in Async HTTP Request [{method}] {url}", config)
        return None
