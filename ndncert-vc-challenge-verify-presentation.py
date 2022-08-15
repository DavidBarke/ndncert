#!/usr/bin/env python3.9
import argparse
import asyncio
import json
import logging
import sys

from aiohttp import ClientSession, ClientResponse

def send_msg(context: str, value: str) -> None:
    """ Print message using a simple protocol: <msg>:{context}:{value}. Message is captured in parent process.

    Args:
        context (str): Message context
        value (str): Message value
    """
    print(f"<msg>:{context}:{value}", flush=True)
    
async def request(
        session, method, path, data=None, text=False, params=None, headers=None
    ) -> ClientResponse:
        """ Send a HTTP request

        Args:
            method (str): HTTP Verb
            path (str): URL path
            data (Dict, optional): Request body. Defaults to None.
            text (bool, optional): If True return response as str, otherwise return response as Dict. Defaults to False.
            params (Dict, optional): URL parameters. Defaults to None.
            headers (Dict, optional): Request headers. Defaults to None.

        Raises:
            Exception: HTTP request failed
            Exception: Response can not be decoded to JSON

        Returns:
            ClientResponse: str or Dict representing the response; depends on text argument
        """
        params = {k: v for (k, v) in (params or {}).items() if v is not None}
        async with session.request(
            method, path, json=data, params=params, headers=headers
        ) as resp:
            resp_text = await resp.text()
            try:
                resp.raise_for_status()
            except Exception as e:
                # try to retrieve and print text on error
                raise Exception(f"Error: {resp_text}") from e
            if not resp_text and not text:
                return None
            if not text:
                try:
                    return json.loads(resp_text)
                except json.JSONDecodeError as e:
                    raise Exception(f"Error decoding JSON: {resp_text}") from e
            return resp_text
    

async def main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--presentation_id", required=True)
    parser.add_argument("--config_file", required=True)
    parser.add_argument("--log", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log), encoding="UTF-8", stream=sys.stdout)
    
    # Read config file
    with open(args.config_file) as f:
        config = json.load(f)
        logging.debug(f"config: {config}")
    endpoint = config["aries-admin-endpoint"]
    logging.info(f"endpoint: {endpoint}")
    
    async with ClientSession() as session:
        # Retrieve presentation exchange record with client agent
        res = await request(session, "get", endpoint + "/present-proof-2.0/records", params={"thread_id": args.presentation_id})
        res = res["results"][0]
        pres_ex_id = res["pres_ex_id"]
        logging.info(f"pres_ex_id: {pres_ex_id}")
        
        if res["state"] != "done":
            # if server agent does not auto-verifiy received presentations, verify manually
            res = await request(session, "post", endpoint + f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation")
        
        verified = res["verified"]
        logging.info(f"verified: {verified}")
        send_msg("verified", verified)
            
    
asyncio.run(main())