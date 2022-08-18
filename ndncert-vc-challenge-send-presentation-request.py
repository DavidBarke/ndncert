#!/usr/bin/env python3.9
import argparse
import asyncio
import json
import logging
import sys
from typing import Dict

from aiohttp import ClientSession, ClientResponse

def send_msg(context: str, value: str) -> None:
    """ Print message using a simple protocol: <msg>:{context}:{value}. Message is captured in parent process.

    Args:
        context (str): Message context
        value (str): Message value
    """
    print(f"<msg>:{context}:{value}", flush=True)

def presentation_proof_send_request_body(connection_id: str, presentation_request: Dict) -> Dict:
    """ Build request body for /present-proof-2.0/send-request

    Args:
        connection_id (str): Connection identifier
        presentation_request (Dict): Presentation request object

    Returns:
        Dict: Request body for /present-proof-2.0/send-request
    """
    return {
        "auto_verify": True,
        "comment": "string",
        "connection_id": connection_id,
        "presentation_request": presentation_request,
        "trace": False
    }
    
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
    parser.add_argument("--connection_did", required=True)
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
    presentation_request = config["presentation-request"]
    logging.info(f"presentation_request: {presentation_request}")
    
    async with ClientSession() as session:
        # Retrieve connection to client agent
        res = await request(session, "get", endpoint + "/connections", params={"their_did": args.connection_did})
        connection_id = res["results"][0]["connection_id"]
        logging.info(f"connection_id: {connection_id}")
        
        # Send presentation request to client agent
        ppsr_body = presentation_proof_send_request_body(connection_id, presentation_request)
        res = await request(session, "post", endpoint + "/present-proof-2.0/send-request", data=ppsr_body)
        thread_id = res["thread_id"]
        logging.info(f"presentation_id: {thread_id}")
        send_msg("presentation_id", thread_id)
            
    
asyncio.run(main())