import argparse
import asyncio
import json

from aiohttp import ClientSession

def format_requested_attribute(pres_ref, cred_id):
    return (
        pres_ref,
        {
            "cred_id": cred_id,
            "revealed": True
        }
    )

def presentation_proof_send_presentation_body(cred_resp):
    presentation_referents = cred_resp["presentation_referents"]
    cred_id = cred_resp["cred_info"]["referent"]
    requested_attributes = [format_requested_attribute(pres_ref, cred_id) for pres_ref in presentation_referents]
    
    return {
        "indy": {
            "requested_attributes": dict(requested_attributes),
            "requested_predicates": {},
            "self_attested_attributes": {},
            "trace": False
        },
        "trace": True
    }

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--thread_id", required=True)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()
    
    async with ClientSession(args.endpoint) as session:
        async with session.request(
            "get", "/present-proof-2.0/records", 
            params={"thread_id": args.thread_id}
        ) as resp:
            text = await resp.text()
            text_json = json.loads(text)
            pres_ex_id = text_json["results"][0]["pres_ex_id"]
            print(pres_ex_id)
            pres_request = text_json["results"][0]["by_format"]["pres_request"]
            print(pres_request)
            
        async with session.request("get", f"/present-proof-2.0/records/{pres_ex_id}/credentials") as resp:
            text = await resp.text()
            text_json = json.loads(text)
            cred_resp = text_json[0]
            print(cred_resp)
                    
        ppsp_body = presentation_proof_send_presentation_body(cred_resp)
        print(ppsp_body)
        async with session.request(
            "post", f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
            json=ppsp_body
        ) as resp:
            text = await resp.text()
            print(text)
    
asyncio.run(main())