import yaml

with open("config.yml") as f:
    cfg = yaml.safe_load(f)

print(cfg["mode"])
