# EUDI Verify Python SDK

Typed, dependency-free Python client for the Attack EUDI Verifier API. The
package is a repository-local PyPI candidate and is not published yet.

## Install

```bash
pip install eudi-verify-sdk
```

Keep the tenant Bearer API key on the server side. Do not embed it in browser
applications.

## Create a presentation request

```python
import os
from eudi_verify_sdk import AttackClient, CreateRequestInput

client = AttackClient(
    os.getenv("ATTACK_URL", "http://127.0.0.1:8080"),
    api_key=os.environ["ATTACK_API_KEY"],
)
request = client.create_presentation_request(
    CreateRequestInput(claims=["age_over_18"])
)
print(request.request_object_uri)
```

## Submit a wallet response

`submit_presentation` does not raise for a rejected presentation. Check `ok`
first, then `valid`, then `error` — `/direct_post` is public, and the HTTP
status says only whether the service could process the presentation, not whether
it is valid:

| `ok` | `valid` | HTTP | Meaning |
|---|---|---|---|
| `False` | `False` | 422 | not processed: unknown session, malformed body, replay, JWE problem |
| `True` | `False` | 200 | processed and rejected on content, e.g. `certificate_expired` |
| `True` | `True` | 200 | valid |

```python
outcome = client.submit_presentation(response=wallet_jwe)
if not outcome.ok:
    print("not processed:", outcome.error)   # 422: unknown_state, state_invalid, …
elif not outcome.valid:
    print("rejected on content:", outcome.error)   # 200, processed and rejected
```

Checking `valid` alone is not sufficient: on a 422 `valid` is `False` as well.

## Read the result and handle errors

```python
from eudi_verify_sdk import ApiError

try:
    result = client.get_result(request.session_id)
    if result.status == "completed":
        print(result.result)
except ApiError as error:
    print(error.status, error.code)
```
