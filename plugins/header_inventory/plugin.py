"""Example passive extension; reads the sanitized scan snapshot."""
def run(context):
    headers = context.snapshot.get("headers") or {}
    context.log(f"Collected {len(headers)} response header names")
    return []
