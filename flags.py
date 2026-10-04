"""Challenge flags; set FLAG1 through FLAG5 in the environment to override them."""

import os


FLAG1 = os.environ.get("FLAG1", "FLAG{ghostyCTF_robots_recon}")
FLAG2 = os.environ.get("FLAG2", "FLAG{ghostyCTF_sql_login_bypassed}")
FLAG3 = os.environ.get("FLAG3", "FLAG{ghostyCTF_idor_admin_profile}")
FLAG4 = os.environ.get("FLAG4", "FLAG{ghostyCTF_command_injection}")
FLAG5 = os.environ.get("FLAG5", "FLAG{ghostyCTF_uploaded_script}")
