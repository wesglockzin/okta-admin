import os
import tempfile

# The app reads its settings when it is imported, so set them first.
os.environ["AUTH_MODE"] = "none"
os.environ["OKTA_ADMIN_ORGS"] = "alpha,beta"
os.environ["OKTA_ADMIN_ALPHA_URL"] = "https://alpha.example.test"
os.environ["OKTA_ADMIN_BETA_URL"] = "https://beta.example.test"
os.environ["ACTION_LOG_PATH"] = os.path.join(tempfile.mkdtemp(), "actions.log")
