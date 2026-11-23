# stackprint (Python client)

A thin client that drives the `stackprint` binary over a pipe. Install the
binary (`go install github.com/Thewildweb/stackprint/cmd/stackprint@latest`),
then:

```python
from stackprint import Scanner

with Scanner() as sc:
    result = sc.scan({"url": "https://example.test/", "html": "<meta name='generator' content='WordPress 6.5'>"})
```

Set `STACKPRINT_BIN` to point at a binary that is not on `PATH`.
