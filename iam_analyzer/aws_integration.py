"""Functions to pull IAM data from a live AWS account using boto3."""
import boto3
from typing import List, Dict

def get_all_policies() -> List[Dict]:
    iam = boto3.client("iam")
    paginator = iam.get_paginator("list_policies")
    policies = []
    for page in paginator.paginate(Scope='Local'):
        for pol in page['Policies']:
            arn = pol['Arn']
            v = iam.get_policy_version(PolicyArn=arn,
                                       VersionId=pol['DefaultVersionId'])
            policies.append({
                "PolicyName": pol['PolicyName'],
                "Arn": arn,
                "Document": v['PolicyVersion']['Document']
            })
    return policies
