import asyncio
import argparse

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


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection_id", required=True)
    parser.add_argument("--cred_def_id", required=True)
    parser.add_argument("--requested_attributes", nargs="*", required=True)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()
    
    cred_def_id = args.cred_def_id
    requested_attributes = [format_requested_attribute(x, i, cred_def_id) for i, x in enumerate(args.requested_attributes)]

    presentation_request = {
        "indy": {
            "name": "NDNCERT Proof",
            "requested_attributes": dict(requested_attributes),
            "requested_predicates": {},
            "version": "1.0"
        }
    }

    presentation_proof_send_request_body = {
        "auto_verify": True,
        "comment": "string",
        "connection_id": args.connection_id,
        "presentation_request": presentation_request,
        "trace": False
    }

    pprint(presentation_proof_send_request_body)
    
    async with ClientSession(args.endpoint) as session:
        async with session.request("post", "/present-proof-2.0/send-request", json=presentation_proof_send_request_body) as resp:
            print(resp.status)
            print(await resp.text())
            
    
asyncio.run(main())