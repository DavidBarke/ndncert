# Verifiable Credentials Challenge (AnonCreds - Hyperledger Indy)

## Overview

- Challenge ID: `vc_indy`
- Description: The CA requires the requester to prove their ownership of a AnonCred
- Required round trips: tba
- Require out-of-band operations: yes
- Mutual verification: maybe
- Time limit: 60 seconds
- Allowed number of attemps: 1

## Challenge Specification
Herausforderung:
- Austausch von VC: könnte über DIDComm oder NDN gesendet werden

# Example Presentation Request
'{"indy": {"name": "NDNCERT Proof", "version": "1.0", "requested_predicates": {}, "requested_attributes": {"attr1": {"name": "score", "restrictions": [{"cred_def_id": "4QxzWk3ajdnEA37NdNU5Kt:3:CL:144152:default"}]}}}}'