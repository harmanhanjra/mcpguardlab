"""MCPGuardLab CLI entry point."""

import argparse
import sys

from mcpguardlab.security import SecurityGuard
from mcpguardlab.simulator import AdversarialSimulator
from mcpguardlab.verify import main as verify_main


def cmd_simulate(args):
    """Run adversarial simulation."""
    sim = AdversarialSimulator(seed=args.seed)
    passed, total = sim.run_tests()
    print(f"Passed: {passed}/{total}")
    sys.exit(0 if passed == total else 1)


def cmd_check(args):
    """Check a single tool call."""
    guard = SecurityGuard()
    valid, error = guard.validate_tool_call(args.tool, args.args or {})
    if valid:
        print(f"VALID: {args.tool}")
        sys.exit(0)
    else:
        print(f"REJECTED: {args.tool} - {error}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='mcpguardlab',
        description='MCP Security Validation Harness'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Run verification harness')
    verify_parser.add_argument('--seed', type=int, default=42)
    verify_parser.add_argument('--trials', type=int, default=100)

    # Simulate command
    sim_parser = subparsers.add_parser('simulate', help='Run adversarial simulation')
    sim_parser.add_argument('--seed', type=int, default=42)

    # Check command
    check_parser = subparsers.add_parser('check', help='Check a tool call')
    check_parser.add_argument('tool', help='Tool name')
    check_parser.add_argument('--args', nargs='*', default=[], help='Arguments')

    args = parser.parse_args()

    if args.command == 'verify':
        verify_main()
    elif args.command == 'simulate':
        cmd_simulate(args)
    elif args.command == 'check':
        cmd_check(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
