import argparse
import asyncio
import json

from pprint import pprint
from aiohttp import ClientSession

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

def presentation_proof_send_request_body(connection_id, cred_def_id, requested_attributes):
    requested_attributes = [format_requested_attribute(x, i, cred_def_id) for i, x in enumerate(requested_attributes)]

    presentation_request = {
        "indy": {
            "name": "NDNCERT Proof",
            "requested_attributes": dict(requested_attributes),
            "requested_predicates": {},
            "version": "1.0"
        }
    }

    return {
        "auto_verify": True,
        "comment": "string",
        "connection_id": connection_id,
        "presentation_request": presentation_request,
        "trace": False
    }
    

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection_did", required=True)
    parser.add_argument("--cred_def_id", required=True)
    parser.add_argument("--requested_attributes", nargs="*", required=True)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()
    
    async with ClientSession(args.endpoint) as session:
        async with session.request("get", "/connections", params={"their_did": args.connection_did}) as resp:
            text = await resp.text()
            text_json = json.loads(text)
            connection_id = text_json["results"][0]["connection_id"]
        
        ppsr_body = presentation_proof_send_request_body(connection_id, args.cred_def_id, args.requested_attributes)
        async with session.request("post", "/present-proof-2.0/send-request", json=ppsr_body) as resp:
            text = await resp.text()
            text_json = json.loads(text)
            thread_id = text_json["thread_id"]
            print(thread_id)
            
    
asyncio.run(main())