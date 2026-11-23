from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .attack_planner import (
    AttackPlan, Strategy, build_plan, execute_plan, RecoveryExhausted,
)
from .crypto_hypotheses import inspect_hypotheses
from .masked_ec_signature import extract_instance as extract_masked_ec, recover_flag as recover_masked_ec_flag
from .affine_ec_leak import extract_instance as extract_affine_ec_leak, recover_flag as recover_affine_ec_leak_flag
from .quaternion_equivalent_key import extract_instance as extract_quaternion_key, recover_flag as recover_quaternion_flag
from .ring_scalar_anonymity import extract_instance as extract_ring_scalar_leak, recover_flag as recover_ring_scalar_leak_flag
from .ring_scalar_anonymity import signer_candidates as ring_signer_candidates
from .polynomial_gcd_prefix import extract_instance as extract_polynomial_gcd_prefix, recover_flag as recover_polynomial_gcd_prefix_flag
from .polynomial_gcd_prefix import construct_input as construct_polynomial_gcd_input
from .weak_seeded_multiprime_rsa import extract_instance as extract_weak_seeded_rsa, recover_flag as recover_weak_seeded_rsa_flag
from .cyclotomic_rsa import extract_instance as extract_cyclotomic_rsa, recover_flag as recover_cyclotomic_rsa_flag
from .modular_noise_mixture import extract_instance as extract_modular_noise, recover_flag as recover_modular_noise_flag
from .biased_shamir import extract_instance as extract_biased_shamir, recover_flag as recover_biased_shamir_flag
from .cookie import main as cookie_main
from .assistant import assistant_session
from .diagnostics import diagnose_runtime
from .dghv_workflow import recover_flag as recover_dghv_flag, supported_source as supported_dghv_source
from .eclcg_workflow import extract_instance as extract_eclcg_instance, recover_flag as recover_eclcg_flag
from .fischlin_workflow import recover_flag as recover_fischlin_flag, supported_source as supported_fischlin_source
from .gcm_hidden_state import recognize_gcm_tag_oracle
from .gcm_hidden_live import (
    recover_flag as recover_gcm_hidden_flag,
    supports_wire_profile as supports_gcm_wire_profile,
)
from .hamiltonicity_workflow import extract_instance as extract_fiat_shamir_graph, recover_flag as recover_fs_graph_flag
from .fiat_shamir_batch import extract_instance as extract_batch_fiat_shamir, recover_flag as recover_batch_fs_flag
from .parser import collect_documents
from .scanner import scan
from .ntru_auto import instances as ntru_instances, recover_flag as recover_ntru_flag
from .stream_combiner_workflow import recognize_stream_cipher, recover_stream_cipher
from .or_sigma import extract_instance as extract_or_schnorr, recover_flag as recover_or_schnorr_flag
from .bounded_ot import extract_instance as extract_bounded_ot, recover_flag as recover_bounded_ot_flag
from .spn_linear_oracle import extract_instance as extract_linear_spn, recover_flag as recover_linear_spn_flag
from .unramified_ring_oracle import extract_instance as extract_unramified, recover_flag as recover_unramified_flag
from .threshold_rsa import extract_instance as extract_truncated_rsa, recover_flag as recover_truncated_rsa_flag
from .groth16_ticket import extract_instance as extract_groth16_tickets, recover_flag as recover_groth16_tickets_flag
from .pairing_confirmation import extract_instance as extract_pairing_confirmation, recover_flag as recover_pairing_confirmation_flag
from .reducible_ring_signature import extract_instance as extract_reducible_glp, recover_flag as recover_reducible_glp_flag
from .terminal_report import render_findings

COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptoscan", description="Deterministic offline CTF cryptography scanner")
    parser.add_argument("targets", nargs="+", help="files or directories to scan; use cryptoscan cookie --help for cookie tools")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    colors = parser.add_mutually_exclusive_group()
    colors.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    colors.add_argument("--color", action="store_true", help="force ANSI colors (useful with redirected output)")
    parser.add_argument("--verbose", "-v", action="store_true", help="show full evidence, solver data and recovery steps")
    parser.add_argument("--assist", action="store_true", help="start guided CLI after scanning, including in non-TTY sessions")
    parser.add_argument("--no-assist", action="store_true", help="never start guided CLI")
    parser.add_argument("--fermat-steps", type=int, default=100_000, help="maximum Fermat iterations per RSA modulus")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit status 1 when findings exist")
    parser.add_argument("--solve", action="store_true", help="run a source-verified supported CTF solver (opt-in network)")
    parser.add_argument("--plan-attacks", action="store_true", help="show applicable attack families and required capabilities without running attacks")
    parser.add_argument("--host", help="authorized CTF service hostname for --solve")
    parser.add_argument("--port", type=int, help="authorized CTF service TCP port for --solve")
    parser.add_argument("--timeout", type=float, default=30.0, help="network socket timeout for --solve")
    parser.add_argument("--bkz-block", type=int, default=20,
                        help="BKZ block size for offline lattice recovery (0 means LLL only)")
    parser.add_argument("--lattice-timeout", type=int, default=900,
                        help="maximum offline lattice worker duration in seconds")
    parser.add_argument("--lattice-backend", choices=("auto", "fplll", "fpylll", "flint", "sympy"),
                        default="auto", help="lattice reduction backend for offline solving")
    parser.add_argument("--seed-search-limit", type=int, default=4096,
                        help="maximum deterministic PRNG seeds for weak-seeded RSA recovery")
    parser.add_argument("--initial-fold", type=int, default=64,
                        help="initial NTRU folding degree, must divide n by a power of two")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _text(findings, color: bool, *, verbose: bool = True) -> str:
    """Compatibility wrapper: direct callers retain the detailed report."""
    return render_findings(findings, color=color, verbose=verbose)


def _execute_recovery(label, solver, *parameters, **options) -> int:
    """Run exactly one proven strategy and report a remotely/locally verified flag."""
    try:
        flag = solver(*parameters, **options)
    except (RuntimeError, ValueError, OSError, ImportError, ArithmeticError) as exc:
        print(f"{label} solver failed: {exc}", file=sys.stderr)
        return 2
    print(f"FLAG: {flag}")
    return 0


def _ring_range_preflight(model):
    """Verify signer response range constraints before attempting AES keys."""
    combinations = 1
    for level in model.levels:
        candidates = ring_signer_candidates(level, model.order)
        if not candidates:
            return False
        combinations *= len(candidates)
        if combinations > 2_000_000:
            return False
    return True


def _attack_strategies(args):
    """Register attack families by verified preconditions, not challenge IDs.

    Construct on demand so test overrides and third-party implementations
    can replace a recognizer or recovery function without stale references.
    """
    def strategy(name, mode, recognize, recover, rank, *,
                 capabilities=(), backend="python", preflight=None):
        return Strategy(name, mode, recognize, recover,
                        tuple(capabilities), rank, backend, preflight)

    offline = (
        strategy("Modular-noise LWE mixture linear distinguisher", "offline",
                 extract_modular_noise, recover_modular_noise_flag, 3),
        strategy("Cyclotomic related RSA finite-field factorization", "offline",
                 extract_cyclotomic_rsa, recover_cyclotomic_rsa_flag, 4),
        strategy("Weak-seeded RSA partial CRT", "offline",
                 extract_weak_seeded_rsa,
                 lambda docs: recover_weak_seeded_rsa_flag(
                     docs, max_seeds=args.seed_search_limit,
                 ), 5),
        strategy("Ring signature scalar distribution", "offline",
                 extract_ring_scalar_leak, recover_ring_scalar_leak_flag, 10,
                 preflight=_ring_range_preflight),
        strategy("Equivalent quaternion conjugator", "offline",
                 extract_quaternion_key, recover_quaternion_flag, 20),
        strategy("Affine EC public-combination discrete log", "offline",
                 extract_affine_ec_leak, recover_affine_ec_leak_flag, 30,
                 backend="sage"),
        strategy("Masked EC signature inlier", "offline",
                 extract_masked_ec, recover_masked_ec_flag, 40),
        strategy("LFSR correlation", "offline",
                 lambda docs: _unique_streams(docs),
                 lambda docs: recover_stream_cipher(_unique_streams(docs)[0]),
                 50),
        strategy("ECDSA-LCG", "offline",
                 extract_eclcg_instance, recover_eclcg_flag, 60),
        strategy("NTRU lattice", "offline",
                 ntru_instances,
                 lambda docs: recover_ntru_flag(
                     docs, bkz=args.bkz_block, backend=args.lattice_backend,
                     initial_degree=args.initial_fold,
                     timeout_seconds=args.lattice_timeout,
                 ), 70),
    )
    def remote(name, recognize, recover, rank, *,
               backend="python", preflight=None):
        return strategy(
            name, "remote", recognize,
            lambda docs: recover(
                docs, args.host, args.port, timeout=args.timeout,
            ), rank, capabilities=("network",), backend=backend,
            preflight=preflight,
        )
    interactive = (
        remote("Biased Shamir coefficient inference + CRT",
               extract_biased_shamir, recover_biased_shamir_flag, 5),
        remote("Polynomial GCD prefix oracle",
               extract_polynomial_gcd_prefix,
               recover_polynomial_gcd_prefix_flag, 10,
               preflight=lambda model: construct_polynomial_gcd_input(model)[1] >= 256),
        remote("Reducible cyclic-ring signature",
               extract_reducible_glp, recover_reducible_glp_flag, 20,
               backend="sage"),
        remote("Groth16 proof-identity replay",
               extract_groth16_tickets, recover_groth16_tickets_flag, 30),
        remote("Pairing confirmation forgery",
               extract_pairing_confirmation, recover_pairing_confirmation_flag, 40,
               backend="sage"),
        remote("Truncated-share RSA",
               extract_truncated_rsa, recover_truncated_rsa_flag, 50),
        remote("Unramified ring evaluation",
               extract_unramified, recover_unramified_flag, 60,
               backend="sage"),
        remote("Chosen-plaintext linear SPN",
               extract_linear_spn, recover_linear_spn_flag, 70),
        remote("Bounded EC-ElGamal OT",
               extract_bounded_ot, recover_bounded_ot_flag, 80),
        remote("OR-Schnorr protocol",
               extract_or_schnorr, recover_or_schnorr_flag, 90),
        remote("Fiat-Shamir transcript-collision",
               extract_batch_fiat_shamir, recover_batch_fs_flag, 100),
        remote("Fiat-Shamir grinding",
               extract_fiat_shamir_graph, recover_fs_graph_flag, 110),
        remote("GCM hidden-state",
               supports_gcm_wire_profile, recover_gcm_hidden_flag, 120),
        remote("Fischlin",
               supported_fischlin_source, recover_fischlin_flag, 130),
        remote("DGHV",
               supported_dghv_source, recover_dghv_flag, 140),
    )
    return offline + interactive


def _unique_streams(documents):
    instances = recognize_stream_cipher(documents)
    if len(instances) > 1:
        raise ValueError("multiple stream cipher instances; choose one corpus")
    return instances


def _candidate_plan(args, documents):
    mode = "remote" if args.host and args.port else "offline"
    capabilities = frozenset({"network"}) if mode == "remote" else frozenset()
    # Each independently scoped CTF is planned in isolation. A directory
    # containing multiple challenge folders must not borrow evidence across
    # unrelated sources or quietly return a flag from the wrong challenge.
    groups = {}
    for document in documents:
        groups.setdefault(document.scope, []).append(document)
    plan = AttackPlan()
    for scope, scoped_documents in sorted(groups.items()):
        scoped = build_plan(
            _attack_strategies(args), scoped_documents, mode=mode,
            capabilities=capabilities, scope=scope,
        )
        plan.candidates.extend(scoped.candidates)
        plan.rejected.extend(scoped.rejected)
    plan.candidates.sort(key=lambda item: (
        item.strategy.rank, item.scope, item.family,
    ))
    return plan


def _execute_attack_plan(args, documents) -> int | None:
    plan = _candidate_plan(args, documents)
    if not plan.candidates:
        return None
    try:
        family, plaintext = execute_plan(plan, documents)
    except RecoveryExhausted as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"FLAG: {plaintext}")
    return 0


def _solve_remote(args, documents) -> int | None:
    return _execute_attack_plan(args, documents)


def _solve_offline(args, documents) -> int | None:
    return _execute_attack_plan(args, documents)


def _solve_documents(args, documents) -> int:
    """Separate solver selection from parsing, scanning and presentation."""
    result = (_solve_remote(args, documents) if args.host and args.port
              else _solve_offline(args, documents))
    if result is not None:
        return result
    print("No supported source-verified solver for these files and endpoint.",
          file=sys.stderr)
    return 2


def _validate_arguments(args) -> None:
    if not 1 <= args.seed_search_limit <= (1 << 20):
        _parser().error("--seed-search-limit must be between 1 and 1048576")
    if args.fermat_steps < 0:
        _parser().error("--fermat-steps must be non-negative")
    if args.assist and args.no_assist:
        _parser().error("--assist and --no-assist cannot be combined")
    if args.solve and (args.format == "json" or args.assist or args.no_assist):
        _parser().error("--solve cannot be combined with --format json, --assist, or --no-assist")
    if (args.solve or args.plan_attacks) and bool(args.host) != bool(args.port):
        _parser().error("--host and --port must be supplied together")
    if args.solve and args.plan_attacks:
        _parser().error("--solve and --plan-attacks cannot be combined")
    if args.assist and args.format == "json":
        _parser().error("--assist cannot be combined with --format json")


def _print_report(args, findings) -> None:
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "findings": [item.to_dict() for item in findings]}, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and os.environ.get("NO_COLOR") is None and (args.color or sys.stdout.isatty())
        print(_text(findings, color, verbose=args.verbose))


def _should_assist(args, findings) -> bool:
    if args.no_assist or args.format != "text":
        return False
    return bool(args.assist or (findings and sys.stdin.isatty() and sys.stdout.isatty()))


def _special_command(arguments: list[str]) -> int | list[str]:
    if arguments and arguments[0] == "doctor":
        return diagnose_runtime()
    if arguments and arguments[0] == "cookie":
        return cookie_main(arguments[1:])
    if arguments and arguments[0] == "assist":
        if len(arguments) == 1:
            assistant_session()
            return 0
        return arguments[1:] + ["--assist"]
    return arguments


def _report_supported_protocols(args, documents) -> None:
    if args.format != "text":
        return
    modular_noise = extract_modular_noise(documents)
    if modular_noise is not None:
        print("Detected: mixed LWE-like samples have a noise component "
              "divisible by a source-proven power of two; group-wise "
              "linear recovery can identify authentic samples "
              f"({modular_noise.key_bytes} key bytes, "
              f"{modular_noise.samples_per_bit} samples per bit, "
              f"noise divisible by 2**{modular_noise.noise_bits}).")
    cyclotomic = extract_cyclotomic_rsa(documents)
    if cyclotomic is not None:
        print("Detected: RSA factors satisfy a cyclotomic geometric-sum "
              "relation; quotient finite-field subgroup collapse can "
              f"recover a factor (extension degree {cyclotomic.degree}).")
    biased_shamir = extract_biased_shamir(documents)
    if biased_shamir is not None:
        print("Detected: Shamir polynomial coefficients sampled from a "
              "proper subset of the field; repeated share observations "
              "can leak the constant term, with cross-field CRT recovery "
              f"({biased_shamir.secret_bits}-bit secret).")
    weak_seeded_rsa = extract_weak_seeded_rsa(documents)
    if weak_seeded_rsa is not None:
        print("Detected: deterministic PRNG seeded from a bounded entropy "
              "source for RSA prime generation; partial factor enumeration "
              "and CRT plaintext recovery available "
              f"(first seed {weak_seeded_rsa.first_seed_bits} bits, "
              f"prime candidates {weak_seeded_rsa.prime_bits} bits).")
    ring_scalar = extract_ring_scalar_leak(documents)
    if ring_scalar is not None:
        print("Detected: ring signature signer anonymity leak from "
              "nonuniform scalar ranges; offline signer candidate filtering "
              "and AES-key verification available "
              f"({len(ring_scalar.levels)} rings).")
    gcd_prefix = extract_polynomial_gcd_prefix(documents)
    if gcd_prefix is not None:
        print("Detected: attacker-controlled polynomial GCD determines "
              "secret output length; resultant and linear-subresultant "
              "modular-root recovery available "
              f"(degrees {gcd_prefix.first.degree()} and "
              f"{gcd_prefix.second.degree()}).")
    quaternion = extract_quaternion_key(documents)
    if quaternion is not None:
        print("Detected: equivalent quaternion conjugation key from "
              "commuting public power and inverse conjugacy; modular "
              "linear-key recovery and offline AES-CBC verification available "
              f"({quaternion.modulus.bit_length()}-bit modulus).")
    affine_ec = extract_affine_ec_leak(documents)
    if affine_ec is not None:
        print("Detected: public affine combinations of elliptic-curve points "
              "expose a hidden scalar relation; independent point recovery "
              f"and smooth-subgroup DLP available ({len(affine_ec.records)} "
              "observations, SageMath worker).")
    model = extract_reducible_glp(documents)
    if model is not None:
        print("Detected: short-secret signature over a reducible cyclic "
              "polynomial ring; component lattice key recovery and CRT "
              f"available (dimension {model.dimension}, SageMath worker).")
    signature = extract_masked_ec(documents)
    if signature is not None:
        print("Detected: source-verified reversible masked EC signature corpus; "
              "hash-filtered inlier recovery and symmetric-key derivation available "
              f"({len(signature.signatures)} candidates, pure Python).")
    groth16_tickets = extract_groth16_tickets(documents)
    if groth16_tickets is not None:
        print("Detected: Groth16 proof-byte identifier replay; proof "
              "rerandomization with invariant pairing equation available "
              f"({groth16_tickets.redemptions_needed} redemptions, pure Python).")
    if extract_pairing_confirmation(documents) is not None:
        print("Detected: pairing-based confirmation protocol exposes a product "
              "of verifier secrets; source-gated signature-confirmation forgery "
              "available (SageMath worker).")
    rsa_shares = extract_truncated_rsa(documents)
    if rsa_shares is not None:
        print("Detected: reshare-dependent truncated RSA private-exponent "
              "polynomial; overdetermined-share totient recovery available "
              f"({rsa_shares.coefficient_count + 1} reshares, pure Python).")
    model = extract_unramified(documents)
    if model is not None:
        print("Detected: polynomial evaluation over isomorphic unramified "
              "2-adic extension rings; SageMath change-of-basis workflow available "
              f"({len(model.rounds)} rounds).")
    if extract_linear_spn(documents) is not None:
        print("Detected: chosen-plaintext recoverable linear/S-box/linear cipher; "
              "single-query permutation decoder available.")
    if extract_bounded_ot(documents) is not None:
        print("Detected: homomorphic encrypted-choice OT without bit-membership proof; "
              "bounded-message recovery supported.")
    if extract_or_schnorr(documents) is not None:
        print("Supported interactive protocol: Schnorr OR proof "
              "(witness, special-soundness extraction, HVZK simulation).")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = _special_command(arguments)
    if isinstance(command, int):
        return command
    args = _parser().parse_args(command)
    _validate_arguments(args)
    documents = collect_documents(args.targets)
    findings = scan(documents, args.fermat_steps)
    if args.plan_attacks and args.format == "json":
        plan = _candidate_plan(args, documents)
        print(json.dumps({
            "schema_version": 1,
            "findings": [item.to_dict() for item in findings],
            "attack_plan": plan.describe(),
        }, sort_keys=True, indent=2, ensure_ascii=False))
        return 0
    _print_report(args, findings)
    _report_supported_protocols(args, documents)
    if args.plan_attacks:
        plan = _candidate_plan(args, documents)
        print("Applicable attack families:")
        for candidate in plan.candidates:
            print(f"  - {candidate.family} ({candidate.strategy.backend})")
        if not plan.candidates:
            print("  none with verified source preconditions")
        if args.verbose:
            for rejected in plan.rejected:
                print(f"  skipped {rejected.family}: {rejected.reason}")
        return 0
    if args.format == "text" and not findings:
        hypotheses = inspect_hypotheses(documents)
        if hypotheses:
            print("Cryptographic attack hypotheses (unverified; not confirmed weaknesses):")
            for hypothesis in hypotheses:
                print(f"  - {hypothesis.family}: {hypothesis.next_checks[0]}.")
    if args.solve:
        return _solve_documents(args, documents)
    if _should_assist(args, findings):
        assistant_session(findings, documents=documents)
    return 1 if args.fail_on_findings and findings else 0
