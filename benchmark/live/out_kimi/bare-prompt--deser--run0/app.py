import yaml

with open("config.yml") as f:
    config = yaml.safe_load(f)  # ponytail: yaml.load() allows arbitrary code execution; safe_load per OWASP rules

print(config["mode"])
