# Project rules

You must write secure code. Follow the OWASP Top 10:
parameterize SQL queries, validate all input at the boundary, encode output
for its sink, never hardcode secrets, use strong modern crypto and CSPRNGs for
tokens, verify TLS and JWT signatures, and avoid eval/exec on dynamic input.
