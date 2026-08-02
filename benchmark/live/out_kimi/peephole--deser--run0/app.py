import yaml

with open("config.yml") as f:
    config = yaml.safe_load(f)  # safe_load: yaml.load can execute arbitrary objects

print(config["mode"])
