"""Playwright hook for ci/ux-qa/ux_crawl.py: stubs the dashboard APIs with the shared proofmock data (same mocks as phone-layout-gate.py)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proofmock import gql, CLUSTER  # noqa: E402


def install(page):
    def route(r):
        u = r.request.url
        if '/api/v2/graphql' in u:
            r.fulfill(json=gql(json.loads(r.request.post_data or '{}')))
        elif '/ha/cluster' in u:
            r.fulfill(json=CLUSTER)
        elif '/api/v1/auth/login' in u:
            r.fulfill(json=dict(access_token='t', refresh_token='r', user=dict(id='1', email='admin@example.com', name='Admin', role='admin')))
        else:
            r.continue_()
    page.route('**/*', route)
