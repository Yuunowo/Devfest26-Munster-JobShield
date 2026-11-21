# BEFORE baseline: same model + tools, no policy layer.
from jobshield.agent import build_agent

root_agent = build_agent(secure=False)
