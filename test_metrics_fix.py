import os
import sys
import json
from datetime import datetime

# Mock config
class Config:
    DATA_DIR = "data"

sys.modules['config'] = Config

# Import metrics module
# We need to make sure it uses our local data dir
from modules.metrics import BiometricMetrics

# Setup data dir for test
if not os.path.exists("data"):
    os.makedirs("data")

# Create a dummy audit log if not exists (though we know it exists on host)
# But we are running in a tool, so we use the existing data/audit/audit_2026-01-03.json
# We need to make sure DATA_DIR points to where the data is.
# The script is running in /home/luuketheone/Desktop/BIOID-MULTIMODAL
# So data/audit is accessible.

def test_metrics_loading():
    print("Testing metrics loading...")
    metrics = BiometricMetrics()
    
    # Force refresh
    metrics.refresh()
    
    genuine = len(metrics.results['genuine'])
    impostor = len(metrics.results['impostor'])
    
    print(f"Genuine: {genuine}")
    print(f"Impostor: {impostor}")
    
    if genuine > 0 or impostor > 0:
        print("SUCCESS: Loaded data from audit logs.")
    else:
        print("FAILURE: No data loaded.")

    # Test report generation
    report = metrics.generate_report()
    print("Report generated successfully.")
    print(json.dumps(report['overall'], indent=2))

if __name__ == "__main__":
    test_metrics_loading()
