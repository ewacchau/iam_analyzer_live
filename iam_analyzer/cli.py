import json, sys, pathlib, click, colorama
from colorama import Fore, Style
from .analyzer import load_policy, analyze_policy
from .aws_integration import get_all_policies

colorama.init()

def print_report(name, result):
    print(f"\n=== {name} ===")
    print(f"Risk score: {result['total_score']}  Level: {result['risk_level']}")
    for f in result['findings']:
        color = Fore.RED if f['score'] >= 25 else Fore.YELLOW
        print(color + f" - {f['issue']} (+{f['score']})" + Style.RESET_ALL)

@click.group()
def cli():
    """IAM Analyzer CLI"""
    pass

@cli.command()
@click.argument('policy_file', type=click.Path(exists=True))
def file(policy_file):
    """Analyze a single POLICY_FILE (JSON)."""
    pol = load_policy(policy_file)
    res = analyze_policy(pol)
    print_report(policy_file, res)

@cli.command()
def live():
    """Analyze live account IAM policies using default AWS credentials."""
    print("Fetching IAM policies...")
    policies = get_all_policies()
    if not policies:
        click.echo("No local customer-managed policies found.")
        return
    for p in policies:
        res = analyze_policy(p['Document'])
        print_report(p['PolicyName'], res)

if __name__ == '__main__':
    cli()
