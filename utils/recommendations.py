from typing import List
import pandas as pd


def recommend_actions(result_df: pd.DataFrame) -> List[str]:
    actions = []
    if (result_df["classification"] == "malicious").any():
        actions.append("Isolate affected hosts or user accounts immediately.")
        actions.append("Block malicious IPs/domains at firewall and proxy.")
        actions.append("Collect forensic artifacts (memory, disk, logs).")
    if (result_df["classification"] == "suspicious").any():
        actions.append("Increase monitoring and enable detailed logging for affected entities.")
        actions.append("Validate user actions with the business owner.")
    if (result_df["classification"] == "benign").all():
        actions.append("No immediate action required; continue routine monitoring.")
    # General
    actions.append("Create/Update incident ticket and document findings.")
    actions.append("Review detection rules to reduce false positives.")
    return actions
