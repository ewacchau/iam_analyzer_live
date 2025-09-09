import json, sys, pathlib, click, colorama
from colorama import Fore, Style
from .analyzer import load_policy, analyze_policy
from .aws_integration import get_all_policies

colorama.init(autoreset=True)

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
@click.argument('policy_file', type=str)
@click.option('--format', 'format_', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--threshold', type=int, default=None, help='Exit non-zero if score >= THRESHOLD')
def file(policy_file, format_, threshold):
    """Analyze a single POLICY_FILE (JSON). Use '-' to read from stdin."""
    try:
        if policy_file == '-':
            pol = json.load(sys.stdin)
            name = '(stdin)'
        else:
            pol = load_policy(policy_file)
            name = policy_file
    except json.JSONDecodeError:
        click.echo('Invalid JSON input', err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f'Error reading policy: {e}', err=True)
        sys.exit(2)
    res = analyze_policy(pol)
    if format_ == 'json':
        click.echo(json.dumps({'name': name, 'result': res}, indent=2))
    else:
        print_report(name, res)
    if threshold is not None and res['total_score'] >= threshold:
        sys.exit(1)

@cli.command()
@click.option('--format', 'format_', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--threshold', type=int, default=None, help='Exit non-zero if any score >= THRESHOLD')
def live(format_, threshold):
    """Analyze live account IAM policies using default AWS credentials."""
    click.echo("Fetching IAM policies...")
    try:
        policies = get_all_policies()
    except Exception as e:
        click.echo(f'Error fetching policies: {e}', err=True)
        sys.exit(2)
    if not policies:
        click.echo("No local customer-managed policies found.")
        return
    reports = []
    for p in policies:
        res = analyze_policy(p['Document'])
        reports.append({'name': p['PolicyName'], 'result': res})
    if format_ == 'json':
        click.echo(json.dumps(reports, indent=2))
    else:
        for rep in reports:
            print_report(rep['name'], rep['result'])
    if threshold is not None and any(r['result']['total_score'] >= threshold for r in reports):
        sys.exit(1)

if __name__ == '__main__':
    cli()
