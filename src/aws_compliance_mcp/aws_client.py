"""Centralised boto3 client factory with optional profile / endpoint override."""

from __future__ import annotations

import os
import boto3
from botocore.config import Config

_RETRY_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"})


def get_client(service: str, region: str | None = None) -> boto3.client:
    """Return a boto3 client for *service* in *region*.

    Region priority:
      1. Explicit ``region`` argument
      2. ``AWS_DEFAULT_REGION`` env-var
      3. boto3 default chain (config file / instance metadata)
    """
    kwargs: dict = {"config": _RETRY_CONFIG}
    effective_region = region or os.getenv("AWS_DEFAULT_REGION")
    if effective_region:
        kwargs["region_name"] = effective_region

    profile = os.getenv("AWS_PROFILE")
    if profile:
        session = boto3.Session(profile_name=profile)
        return session.client(service, **kwargs)

    return boto3.client(service, **kwargs)
