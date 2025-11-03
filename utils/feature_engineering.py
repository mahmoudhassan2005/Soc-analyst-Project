import ipaddress
import pandas as pd
import numpy as np
from typing import List, Dict


BASE_NUMERIC_FEATURES = [
    "hour",
    "is_weekend",
    "src_is_private",
    "dst_is_private",
    "src_ip_int",
    "dst_ip_int",
]

CATEGORICAL_FEATURES = [
    "event_type",
    "username",
    "status",
]

ALIASES: Dict[str, str] = {
    # timestamp
    "@timestamp": "timestamp",
    "time": "timestamp",
    "date": "timestamp",
    "datetime": "timestamp",
    "date_time": "timestamp",
    "event_time": "timestamp",
    "event_time_utc": "timestamp",
    "timestamp_utc": "timestamp",
    "timecreated": "timestamp",
    "eventreceivedtime": "timestamp",
    "event_received_time": "timestamp",
    "log_time": "timestamp",
    "logtime": "timestamp",
    "created": "timestamp",
    "recorded_time": "timestamp",
    "recordtime": "timestamp",
    # source ip
    "src": "source_ip",
    "src_ip": "source_ip",
    "sip": "source_ip",
    "source": "source_ip",
    "sourceaddress": "source_ip",
    "source_address": "source_ip",
    # destination ip
    "dst": "destination_ip",
    "dst_ip": "destination_ip",
    "dip": "destination_ip",
    "destination": "destination_ip",
    "destinationaddress": "destination_ip",
    "destination_address": "destination_ip",
    # event type
    "event": "event_type",
    "eventid": "event_type",
    "event_id": "event_type",
    "eventtype": "event_type",
    "eventname": "event_type",
    "event_name": "event_type",
    "eventcode": "event_type",
    "event_code": "event_type",
    "provider": "event_type",
    "task": "event_type",
    "opcode": "event_type",
    # username
    "user": "username",
    "user_name": "username",
    "useraccount": "username",
    "user_account": "username",
    "account": "username",
    "accountname": "username",
    "account_name": "username",
    "subjectusername": "username",
    "subject_user_name": "username",
    "logon_account": "username",
    # status/outcome
    "result": "status",
    "outcome": "status",
    "action": "status",
}


def ip_to_int(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def is_private(ip: str) -> int:
    try:
        return 1 if ipaddress.ip_address(ip).is_private else 0
    except Exception:
        return 0


def _ensure_series(df: pd.DataFrame, column: str, default_value) -> pd.Series:
    if column in df.columns:
        val = df[column]
        if isinstance(val, pd.Series):
            return val
        return pd.Series([val] * len(df))
    return pd.Series([default_value] * len(df))


def canonicalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names and map common aliases to expected names."""
    if df is None or df.empty:
        return df
    new_df = df.copy()
    # normalize: lower, strip, replace spaces and dashes with underscores
    norm_map = {}
    for c in list(new_df.columns):
        norm = str(c).strip().lower().replace(" ", "_").replace("-", "_")
        norm_map[c] = norm
    new_df.rename(columns=norm_map, inplace=True)

    # apply alias mapping
    for alias, target in ALIASES.items():
        if alias in new_df.columns and target not in new_df.columns:
            new_df.rename(columns={alias: target}, inplace=True)
    return new_df


def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = canonicalize_columns(df)
    df = df.copy()

    # timestamp-derived - ensure a Series, not a scalar NaT
    if "timestamp" in df.columns and isinstance(df["timestamp"], pd.Series):
        ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    else:
        ts = pd.Series([pd.NaT] * len(df), dtype="datetime64[ns, UTC]")
    df["hour"] = ts.dt.hour.fillna(0).astype(int)
    df["is_weekend"] = ts.dt.dayofweek.isin([5, 6]).fillna(False).astype(int)

    # IP features (force Series)
    src_ip_series = _ensure_series(df, "source_ip", "").fillna("")
    dst_ip_series = _ensure_series(df, "destination_ip", "").fillna("")

    df["src_ip_int"] = src_ip_series.apply(ip_to_int)
    df["dst_ip_int"] = dst_ip_series.apply(ip_to_int)
    df["src_is_private"] = src_ip_series.apply(is_private)
    df["dst_is_private"] = dst_ip_series.apply(is_private)

    # Ensure categorical columns exist as Series
    for col in CATEGORICAL_FEATURES:
        if col not in df.columns or not isinstance(df[col], pd.Series):
            df[col] = pd.Series(["unknown"] * len(df))

    # Categorical one-hot
    cat_df = pd.get_dummies(
        df[CATEGORICAL_FEATURES].fillna("unknown"),
        prefix=CATEGORICAL_FEATURES,
        dtype=np.uint8,
    )

    X = pd.concat([df[BASE_NUMERIC_FEATURES], cat_df], axis=1)
    # Ensure numeric types
    for c in BASE_NUMERIC_FEATURES:
        if X[c].dtype.kind not in ("i", "u", "f"):
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)
    X = X.fillna(0)
    return X


def align_features(X: pd.DataFrame, feature_names: List[str]) -> pd.DataFrame:
    X = X.copy()
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0
    # drop unexpected columns
    X = X[feature_names]
    X = X.fillna(0)
    return X
