import pandas as pd

def extract_features(conn_log_path="conn.log"):
    """
    Extract ML-ready features from Zeek conn.log
    """

    df = pd.read_csv(
        conn_log_path,
        sep="\t",
        comment="#",
        header=None,
        engine="python"
    )

    df.columns = [
        "ts","uid","src_ip","src_port","dst_ip","dst_port",
        "proto","service","duration",
        "orig_bytes","resp_bytes","conn_state",
        "local_orig","local_resp","missed_bytes",
        "history","orig_pkts","orig_ip_bytes",
        "resp_pkts","resp_ip_bytes","tunnel_parents"
    ]

    # Drop rows without duration
    df = df[df["duration"].notna()]

    features = {
        "event_rate": len(df),
        "avg_duration": float(df["duration"].mean()),
        "failed_ratio": float((df["conn_state"] != "SF").mean()),
        "unique_dsts": int(df["dst_ip"].nunique()),
        "byte_ratio": float(
            (df["orig_bytes"].sum() + 1) /
            (df["resp_bytes"].sum() + 1)
        )
    }

    return features
