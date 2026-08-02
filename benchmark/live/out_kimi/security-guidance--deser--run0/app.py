import yaml

with open("config.yml") as f:
    print(yaml.safe_load(f)["mode"])
