import json
import yaml

json.loads(text)
yaml.safe_load(text)
yaml.load(text, Loader=yaml.SafeLoader)
