#!/usr/bin/env python3.9
import argparse
import asyncio
import json

from pprint import pprint
from aiohttp import ClientSession, ClientResponse

def format_requested_attribute(attr, index, cred_def_id):
    attr_label = "attr" + str(index)
    return (
        attr_label,
        {
            "name": attr,
            "restrictions": [{
                "cred_def_id": cred_def_id
            }]
        }
    )

def presentation_proof_send_request_body(connection_id, presentation_request):
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection_did", required=True)
    parser.add_argument("--config_file", required=True)
    args = parser.parse_args()
    with open(args.config_file) as f:
        config = json.load(f)
        print(config)
    endpoint = config["aries-admin-endpoint"]
    print(endpoint)
    presentation_request = config["presentation-request"]
    print(presentation_request)
    
    async with ClientSession() as session:
        res = await request(session, "get", endpoint + "/connections", params={"their_did": args.connection_did})
        connection_id = res["results"][0]["connection_id"]
        print(f"connection_id: {connection_id}")
        
        ppsr_body = presentation_proof_send_request_body(connection_id, presentation_request)
        res = await request(session, "post", endpoint + "/present-proof-2.0/send-request", data=ppsr_body)
        thread_id = res["thread_id"]
        print(f"thread_id: {thread_id}")
            
    
asyncio.run(main())