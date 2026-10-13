#!/usr/bin/env python3
"""Check the finite public Gate 0 reference corpus without network access."""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "fixtures" / "reference-v1.json"
DIGEST_PATH = ROOT / "fixtures" / "reference-v1.json.sha256"

EXPECTED_LIMITS = {
    "url_key_bytes": 2048,
    "redirect_hops": 10,
    "compressed_response_bytes": 2 * 1024 * 1024,
    "decoded_response_bytes": 8 * 1024 * 1024,
    "html_parser_events": 250000,
    "html_nesting_depth": 256,
    "title_bytes": 4096,
    "combined_fields_bytes": 1024 * 1024,
    "document_tokens": 100000,
    "token_codepoints": 64,
    "phrase_tokens": 16,
    "query_bytes": 4096,
    "query_token_occurrences": 64,
    "links_per_document": 5000,
}

EXPECTED_LIMIT_OUTCOMES = {
    "url_key_bytes": ("accept_key", "reject_url"),
    "redirect_hops": ("continue_chain", "reject_chain_retain_previous"),
    "compressed_response_bytes": ("accept_body", "reject_response_retain_previous"),
    "decoded_response_bytes": ("accept_body", "reject_response_retain_previous"),
    "html_parser_events": ("continue_parse", "reject_document_retain_previous"),
    "html_nesting_depth": ("continue_parse", "reject_document_retain_previous"),
    "title_bytes": ("accept_field", "reject_document_retain_previous"),
    "combined_fields_bytes": ("accept_fields", "reject_document_retain_previous"),
    "document_tokens": ("accept_document", "reject_document_retain_previous"),
    "token_codepoints": ("accept_token", "TokenTooLong"),
    "phrase_tokens": ("accept_phrase", "PhraseTooLong"),
    "query_bytes": ("pass_byte_limit", "QueryTooLong"),
    "query_token_occurrences": ("accept_query", "TooManyTerms"),
    "links_per_document": ("accept_links", "keep_first_5000"),
}

EXPECTED_URL_GOLDENS = {
    "https://example.test/%2e%2e/a/%7euser": {"expected": "https://example.test/a/~user"},
    "https://BÜCHER.example/Über?x=1#top": {"expected": "https://xn--bcher-kva.example/%C3%9Cber?x=1"},
    "https://example.test/a%2fb": {"expected": "https://example.test/a%2Fb"},
    "https://example.test/search?a=1&a=2&x=": {"expected": "https://example.test/search?a=1&a=2&x="},
    "https://example.test/search?": {"expected": "https://example.test/search?"},
    "https://example.test/?q=%7e": {"expected": "https://example.test/?q=~"},
    "https://example.test/caf%c3%a9": {"expected": "https://example.test/caf%C3%A9"},
    " https://example.test/trim ": {"expected": "https://example.test/trim"},
    "https://example.test/%zz": {"error": "malformed_percent_escape"},
    "https://@example.test/private": {"error": "userinfo"},
    "ftp://example.test/file": {"error": "unsupported_scheme"},
}

EXPECTED_EXTRACTION = {
    "html5-fields-and-link-base": {
        "title": "Stone & SKY",
        "body": "Alpha Beta. Gamma Hidden Delta Go",
        "links": ["https://example.test/guide/child"],
    },
    "javascript-base_falls_back_without_later_repair": {
        "title": "Base fallback",
        "body": "Next",
        "links": ["https://example.test/dir/child"],
    },
}

EXPECTED_AST = {
    "alpha_term": {"term": "alpha"},
    "operator_precedence": {
        "or": [{"term": "alpha"}, {"and": [{"term": "beta"}, {"term": "gamma"}]}]
    },
    "cross_field_and": {"and": [{"term": "beta"}, {"term": "gamma"}]},
    "phrase_same_field": {"phrase": ["field", "separation"]},
    "duplicate_terms": {"and": [{"term": "alpha"}, {"term": "alpha"}]},
    "lowercase_operator_word": {"term": "and"},
    "unicode_full_case_fold": {"term": "strasse"},
    "unicode_composed_query": {"term": "café"},
    "unicode_decomposed_query": {"term": "café"},
    "accent_preserved": {"term": "cafe"},
    "unicode_single_token_phrase": {"phrase": ["café"]},
    "shared_exact_tie": {"term": "shared"},
}

EXPECTED_ERRORS = {
    "": "EmptyQuery",
    "   ": "EmptyQuery",
    "!!!": "NoSearchTerms",
    "alpha OR": "MissingOperand",
    "OR alpha": "MissingOperand",
    "NOT alpha": "UnsupportedSyntax",
    "(alpha)": "UnsupportedSyntax",
    "title:alpha": "UnsupportedSyntax",
    "alpha*": "UnsupportedSyntax",
    '""': "EmptyPhrase",
    '"field': "UnterminatedPhrase",
    '"field\\q"': "InvalidEscape",
    '"!!!"': "EmptyPhrase",
}

EXPECTED_REMOVAL_GOLDENS = {
    "other_bot_combined_header_ignored": ("v1", True, 0),
    "repeated_other_bot_fields_keep_scope": ("v1", True, 0),
    "repeated_fields_have_independent_scope": ("v1", False, 0),
    "generic_directive_survives_other_agent_field": ("v1", False, 0),
    "generic_none_means_noindex_nofollow": (None, False, 0),
    "leybot_none_means_noindex_nofollow": (None, False, 0),
    "embedded_agent_prefix_is_not_new_scope": (None, True, 0),
    "generic_noindex_before_unavailable_after": (None, True, 0),
    "generic_none_before_max_snippet": (None, False, 0),
    "generic_noindex_before_embedded_other_agent_prefix": (None, True, 0),
    "generic_unavailable_after_before_noindex": (None, True, 0),
    "generic_max_snippet_before_none": (None, False, 0),
    "generic_max_image_preview_value_none_before_noindex": (None, True, 0),
    "generic_noindex_before_max_image_preview_value_none": (None, True, 0),
    "generic_max_video_preview_before_none": (None, False, 0),
    "generic_none_before_max_video_preview": (None, False, 0),
    "repeated_generic_noindex_then_unavailable_after": (None, True, 0),
    "repeated_unavailable_after_then_generic_noindex": (None, True, 0),
    "repeated_generic_none_then_max_snippet": (None, False, 0),
    "repeated_max_snippet_then_generic_none": (None, False, 0),
    "leybot_scope_survives_max_snippet_item": (None, False, 0),
    "leybot_scope_survives_unavailable_after_item": (None, False, 0),
    "otherbot_scope_isolated_with_colon_directive": ("v1", True, 0),
    "generic_noindex_and_otherbot_nofollow": (None, True, 0),
    "otherbot_nofollow_and_generic_noindex": (None, True, 0),
    "malformed_leading_agent_text_preserves_suffix_and_later_rule": (None, False, 0),
    "malformed_empty_scope_preserves_suffix_and_later_none": (None, False, 0),
    "malformed_later_item_preserves_valid_items": (None, False, 0),
    "malformed_supported_directive_colon_keeps_later_nofollow": ("v1", False, 0),
    "malformed_leading_text_preserves_suffix_and_later_noindex": (None, False, 0),
    "other_bot_none_ignored": ("v1", True, 0),
    "unknown_unrelated_directive_ignored": ("v1", True, 0),
}

X_ROBOTS_SUPPORTED_DIRECTIVES = {"noindex", "nofollow", "none"}
X_ROBOTS_RECOGNIZED_NAMES = {
    "all",
    "indexifembedded",
    "max-image-preview",
    "max-snippet",
    "max-video-preview",
    "noarchive",
    "nocache",
    "noimageindex",
    "noindex",
    "nofollow",
    "none",
    "nositelinkssearchbox",
    "nosnippet",
    "notranslate",
    "unavailable_after",
}
X_ROBOTS_AGENT_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")

EXPECTED_LIFECYCLE_REVIEW_OUTCOMES = {
    "stale_upsert_is_not_acknowledged_publication": "stale_fence_rejected_unacknowledged",
    "exact_old_upsert_replay_after_newer_tombstone": "idempotent_replay_noop",
    "same_fence_upsert_conflicts_with_tombstone": "same_fence_conflict_rejected",
    "first_tombstone_blocks_same_fence_upsert": "same_fence_conflict_rejected",
    "revocation_blocks_automatic_recovery_lease": "revoked_policy_lease_rejected",
    "revocation_blocks_automatic_recovery_upsert": "revoked_policy_upsert_rejected",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def tokenize_example(text: str) -> tuple[str, list[str]]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    tokens = re.findall(r"[^\W_]+", normalized, flags=re.UNICODE)
    return normalized, tokens


def field_bytes(title: str, body: str) -> bytes:
    title_bytes = title.encode("utf-8")
    body_bytes = body.encode("utf-8")
    return (
        struct.pack(">I", len(title_bytes))
        + title_bytes
        + struct.pack(">I", len(body_bytes))
        + body_bytes
    )


def document_hashes(title: str, body: str, extractor_id: str, analyzer_id: str) -> tuple[str, str]:
    fields = field_bytes(title, body)
    content_hash = hashlib.sha256(fields).hexdigest()
    version = (
        b"ley-document-version-v1\0"
        + extractor_id.encode("utf-8")
        + b"\0"
        + analyzer_id.encode("utf-8")
        + b"\0"
        + fields
    )
    return content_hash, hashlib.sha256(version).hexdigest()


def has_term(document: dict, term: str) -> bool:
    return term in document["title_tokens"] or term in document["body_tokens"]


def phrase_in_field(document: dict, field: str, phrase: list[str]) -> bool:
    tokens = document[f"{field}_tokens"]
    width = len(phrase)
    return width > 0 and any(tokens[i : i + width] == phrase for i in range(len(tokens) - width + 1))


def finite_match(document: dict, case: str) -> bool:
    if case == "term_alpha":
        return has_term(document, "alpha")
    if case == "term_and":
        return has_term(document, "and")
    if case == "term_shared":
        return has_term(document, "shared")
    if case == "term_strasse":
        return has_term(document, "strasse")
    if case == "term_cafe_accent":
        return has_term(document, "café")
    if case == "term_cafe_unaccented":
        return has_term(document, "cafe")
    if case == "alpha_or_beta_and_gamma":
        return has_term(document, "alpha") or (has_term(document, "beta") and has_term(document, "gamma"))
    if case == "beta_and_gamma":
        return has_term(document, "beta") and has_term(document, "gamma")
    if case == "phrase_field_separation":
        return phrase_in_field(document, "title", ["field", "separation"]) or phrase_in_field(
            document, "body", ["field", "separation"]
        )
    if case == "phrase_cafe_accent":
        return phrase_in_field(document, "title", ["café"]) or phrase_in_field(document, "body", ["café"])
    raise ValueError(f"unknown finite match case: {case}")


def corpus_stats(documents: list[dict], terms: list[str]) -> dict:
    count = len(documents)
    stats = {"N": count}
    for field in ("title", "body"):
        token_key = f"{field}_tokens"
        total_length = sum(len(document[token_key]) for document in documents)
        dfs = {
            term: sum(term in set(document[token_key]) for document in documents)
            for term in sorted(set(terms), key=lambda value: value.encode("utf-8"))
        }
        stats[field] = {"avg_length": total_length / count if count else 0.0, "df": dfs}
    return stats


def bm25_components(document: dict, documents: list[dict], terms: list[str]) -> dict[str, dict[str, float]]:
    stats = corpus_stats(documents, terms)
    count = stats["N"]
    if count == 0:
        return {term: {"title": 0.0, "body": 0.0} for term in set(terms)}
    components: dict[str, dict[str, float]] = {}
    for term in sorted(set(terms), key=lambda value: value.encode("utf-8")):
        components[term] = {}
        for field, weight in (("title", 2.0), ("body", 1.0)):
            token_key = f"{field}_tokens"
            tokens = document[token_key]
            frequency = tokens.count(term)
            average_length = stats[field]["avg_length"]
            document_frequency = stats[field]["df"][term]
            if frequency == 0 or average_length == 0.0:
                components[term][field] = 0.0
                continue
            inverse_frequency = math.log(1.0 + (count - document_frequency + 0.5) / (document_frequency + 0.5))
            length_norm = 1.0 - 0.75 + 0.75 * len(tokens) / average_length
            components[term][field] = weight * inverse_frequency * frequency * 2.2 / (frequency + 1.2 * length_norm)
    return components


def bm25_score(document: dict, documents: list[dict], terms: list[str]) -> float:
    return sum(
        component
        for fields in bm25_components(document, documents, terms).values()
        for component in fields.values()
    )


def near(actual: float, expected: float, label: str) -> None:
    require(math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12), f"{label}: {actual} != {expected}")


def lifecycle_stats(live: dict[str, dict]) -> dict:
    documents = list(live.values())
    return corpus_stats(documents, ["alpha", "beta", "gamma"])


def lifecycle_identity(event: dict) -> tuple:
    document_id = event["document_id"]
    fence = event["fence"]
    if event["kind"] == "lease":
        return ("lease", document_id, fence)
    if event["kind"] == "upsert":
        return (document_id, fence, "Upsert", event["version"])
    if event["kind"] == "delete":
        return (document_id, fence, "Tombstone")
    raise ValueError(f"unknown lifecycle event kind: {event['kind']}")


def removal_outcome(vector: dict) -> tuple[str | None, bool | None, int]:
    prior = vector["prior_version"]
    directives: list[str] = []
    headers = vector.get("headers", [])
    require(isinstance(headers, list), f"header fields must preserve repeated values: {vector['id']}")
    for field in headers:
        require(set(field) == {"name", "value"}, f"malformed header field: {vector['id']}")
        if not isinstance(field["name"], str) or not isinstance(field["value"], str):
            raise ValueError(f"header name and value must be strings: {vector['id']}")
        if field["name"].lower() != "x-robots-tag":
            continue
        items = field["value"].split(",")
        leading_item = items[0].strip()
        if ":" in leading_item:
            prefix, first_value = leading_item.split(":", 1)
            prefix = prefix.strip()
            name = prefix.lower()
            if name in X_ROBOTS_RECOGNIZED_NAMES:
                items = items[1:]
            elif not X_ROBOTS_AGENT_TOKEN.fullmatch(prefix) or not first_value.strip():
                items[0] = first_value
            elif name != "leybot":
                continue
            else:
                items[0] = first_value
        for item in items:
            item = item.strip()
            if ":" in item:
                continue
            directive = item.lower()
            if directive in X_ROBOTS_SUPPORTED_DIRECTIVES:
                if directive == "none":
                    directives.extend(("noindex", "nofollow"))
                else:
                    directives.append(directive)
    meta = vector.get("meta")
    if meta is not None and meta.get("name", "").lower() in {"robots", "leybot"}:
        for item in meta.get("content", "").split(","):
            directive = item.strip().lower()
            if directive == "none":
                directives.extend(("noindex", "nofollow"))
            elif directive in {"noindex", "nofollow"}:
                directives.append(directive)
    if "noindex" in directives:
        return None, "nofollow" not in directives, 0
    if vector.get("request") in {"source_owner_removal", "policy_retention_deadline", "policy_revocation"}:
        return None, None, 0
    if vector.get("status") == 410:
        return None, None, 0
    if "nofollow" in directives:
        return prior, False, 0
    if vector.get("fetch_performed") is False or vector.get("robots_allowed") is False:
        return prior, None, 0
    if vector.get("decoded_bytes", 0) > EXPECTED_LIMITS["decoded_response_bytes"]:
        return prior, None, 0

    consecutive_404 = 0
    for scheduled_fetch in vector.get("fetches", []):
        attempts = scheduled_fetch["attempts"]
        if not attempts:
            raise ValueError(f"scheduled fetch has no attempts: {vector['id']}")
        terminal = attempts[-1]
        if terminal in {"timeout", "connection_error"}:
            continue
        if terminal == 404:
            consecutive_404 += 1
        else:
            consecutive_404 = 0
    return (None if consecutive_404 >= 2 else prior), "nofollow" not in directives, consecutive_404


def admission_outcome(vector: dict) -> str:
    source = vector["source"]
    policy = vector["policy"]
    if source == "authored_local_fixture" and policy == "project_owned_cc0" and not vector["public_fetch"]:
        return "allow_fixture_only"
    if policy is None:
        return "deny_missing_policy"
    if source == "external_origin" and not vector["public_fetch"]:
        return "deny_public_fetch_disabled"
    if source == "redirect_target" and policy == "not_in_scope":
        return "deny_target"
    raise ValueError(f"unknown finite admission vector: {vector}")


def verify_lifecycle(lifecycle: dict) -> None:
    live: dict[str, dict] = {}
    versions: dict[str, str] = {}
    fences: dict[str, int] = {}
    seen: dict[tuple, dict] = {}
    terminal_intents: dict[tuple[str, int], tuple] = {}
    revoked_policy: set[str] = set()
    operation_ids: dict[str, tuple] = {}
    observed_review_cases: dict[str, str] = {}
    expected_after = lifecycle["expected_live_after_each"]
    require(len(expected_after) == len(lifecycle["events"]), "lifecycle checkpoint count differs from event count")

    for index, event in enumerate(lifecycle["events"], start=1):
        operation_id = event["operation_id"]
        identity = lifecycle_identity(event)
        prior_operation_identity = operation_ids.get(operation_id)
        require(
            prior_operation_identity is None or prior_operation_identity == identity,
            f"operation id {operation_id} was reused for a different typed tuple",
        )
        operation_ids[operation_id] = identity
        prior = seen.get(identity)
        if prior is not None:
            fixture_metadata = {"expected_outcome", "operation_id", "review_case"}
            prior_payload = {key: value for key, value in prior.items() if key not in fixture_metadata}
            event_payload = {key: value for key, value in event.items() if key not in fixture_metadata}
            require(prior_payload == event_payload, f"typed operation {identity} was reused with different contents")
            outcome = "idempotent_replay_noop"
        else:
            document_id = event["document_id"]
            fence = event["fence"]
            require(0 < fence < 2**64, f"fence is outside the u64 range at event {index}")
            current_fence = fences.get(document_id, 0)
            if event["kind"] == "lease":
                if document_id in revoked_policy:
                    outcome = "revoked_policy_lease_rejected"
                else:
                    require(fence > current_fence, f"lease fence did not advance at event {index}")
                    fences[document_id] = fence
                    seen[identity] = event
                    outcome = "lease_issued"
            else:
                intent_key = (document_id, fence)
                prior_intent = terminal_intents.get(intent_key)
                if fence < current_fence:
                    outcome = "stale_fence_rejected_unacknowledged"
                elif prior_intent is not None and prior_intent != identity:
                    outcome = "same_fence_conflict_rejected"
                elif document_id in revoked_policy and event["kind"] == "upsert":
                    outcome = "revoked_policy_upsert_rejected"
                else:
                    require(fence == current_fence and current_fence > 0, f"operation used an unissued fence at event {index}")
                    terminal_intents[intent_key] = identity
                    seen[identity] = event
                    if event["kind"] == "upsert":
                        live[document_id] = {
                            "id": document_id,
                            "title_tokens": event["title_tokens"],
                            "body_tokens": event["body_tokens"],
                        }
                        versions[document_id] = event["version"]
                        outcome = "published"
                    elif event["kind"] == "delete":
                        live.pop(document_id, None)
                        versions.pop(document_id, None)
                        if event.get("cause") == "policy_revocation":
                            revoked_policy.add(document_id)
                        outcome = "tombstone_published"
                    else:
                        raise ValueError(f"unknown lifecycle event kind: {event['kind']}")
        require(
            outcome == event["expected_outcome"],
            f"lifecycle outcome differs at event {index}: {outcome!r} != {event['expected_outcome']!r}",
        )
        review_case = event.get("review_case")
        if review_case is not None:
            require(review_case not in observed_review_cases, f"duplicate lifecycle review case: {review_case}")
            observed_review_cases[review_case] = outcome

        observed = dict(versions)
        require(observed == expected_after[index - 1], f"lifecycle live set differs after event {index}")

        expected_stats = lifecycle["expected_statistics_after_event"].get(str(index))
        if expected_stats is not None:
            actual_stats = lifecycle_stats(live)
            require(actual_stats["N"] == expected_stats["N"], f"lifecycle N differs after event {index}")
            for field in ("title", "body"):
                near(actual_stats[field]["avg_length"], expected_stats[field]["avg_length"], f"lifecycle {field} average at {index}")
                require(actual_stats[field]["df"] == expected_stats[field]["df"], f"lifecycle {field} df differs at {index}")

    require(fences == lifecycle["expected_fence_high_water"], "fence high-water state differs after lifecycle trace")
    require(
        observed_review_cases == EXPECTED_LIFECYCLE_REVIEW_OUTCOMES,
        "lifecycle review cases or outcomes differ from the independently pinned expectations",
    )

    for window in lifecycle["recovery_windows"]:
        if window["recovery"] == "refetch":
            require(not window["outbox_pending"], f"{window['name']} should have no durable intent")
            result = window["manifest"]
        elif window["recovery"] == "replay":
            require(window["outbox_pending"], f"{window['name']} needs a durable intent")
            result = dict(window["manifest"])
            result["mutable"] = window["replay_version"]
        elif window["recovery"] == "ack_noop":
            require(window["outbox_pending"], f"{window['name']} needs an unacknowledged intent")
            result = window["manifest"]
        else:
            raise ValueError(f"unknown recovery action: {window['recovery']}")
        require(result == window["expected_manifest"], f"recovery result differs for {window['name']}")


def verify() -> None:
    corpus_bytes = CORPUS_PATH.read_bytes()
    expected_digest = DIGEST_PATH.read_text(encoding="ascii").split()[0]
    actual_digest = hashlib.sha256(corpus_bytes).hexdigest()
    require(actual_digest == expected_digest, "reference corpus SHA-256 does not match its sidecar")
    corpus = json.loads(corpus_bytes)

    require(corpus["schema"] == "ley-reference-corpus/v1", "unsupported corpus schema")
    require(corpus["license"] == "CC0-1.0", "fixture data license identifier changed")
    require(corpus["contract"]["limits"] == EXPECTED_LIMITS, "fixture limits differ from the Gate 0 contract")
    limit_vectors = {vector["limit"]: vector for vector in corpus["limit_vectors"]}
    require(
        len(limit_vectors) == len(corpus["limit_vectors"])
        and set(limit_vectors) == set(EXPECTED_LIMIT_OUTCOMES),
        "limit vector set differs from the accepted bounds",
    )
    for name, vector in limit_vectors.items():
        at_outcome, over_outcome = EXPECTED_LIMIT_OUTCOMES[name]
        limit = EXPECTED_LIMITS[name]
        require(vector["at"] == limit and vector["over"] == limit + 1, f"boundary counts differ for {name}")
        require(vector["at_outcome"] == at_outcome and vector["over_outcome"] == over_outcome, f"boundary outcome differs for {name}")

    url_outcomes = {}
    url_vectors = {}
    for vector in corpus["url_vectors"]:
        require(("expected" in vector) != ("error" in vector), f"URL vector must have one outcome: {vector['input']}")
        outcome = {key: vector[key] for key in ("expected", "error") if key in vector}
        require(vector["input"] not in url_vectors, f"duplicate URL input vector: {vector['input']}")
        url_vectors[vector["input"]] = outcome
        if "expected" in vector:
            require(len(vector["expected"].encode("utf-8")) <= EXPECTED_LIMITS["url_key_bytes"], "URL key limit vector exceeds the limit")
            require("#" not in vector["expected"], f"URL key retained a fragment: {vector['input']}")
            url_outcomes[vector["input"]] = vector["expected"]
    require(
        all(url_vectors.get(input_value) == outcome for input_value, outcome in EXPECTED_URL_GOLDENS.items()),
        "representative URL golden differs from the independently reviewed outcomes",
    )
    for left, right in (
        ("https://example.test/a%2fb", "https://example.test/a/b"),
        ("https://example.test/search?a=1&a=2&x=", "https://example.test/search?b=2&a=1"),
        ("https://example.test/path/", "https://example.test/path"),
        ("https://example.test/Case", "https://example.test/case"),
        ("https://example.test/path", "https://www.example.test/path"),
        ("https://example.test/path", "http://example.test/path"),
    ):
        require(url_outcomes[left] != url_outcomes[right], f"URL identity distinction collapsed: {left} / {right}")
    for left, right in (
        ("https://example.test:443/path", "https://example.test/path"),
        ("https://example.test/search?q=ley#section", "https://example.test/search?q=ley"),
    ):
        require(url_outcomes[left] == url_outcomes[right], f"URL normalization equivalence differs: {left} / {right}")
    require(url_outcomes["https://example.test/?q=%7e"] == "https://example.test/?q=~", "unreserved query escape was not normalized")
    require(url_outcomes["https://example.test/path?utm_source=local"].endswith("?utm_source=local"), "unknown query parameter was stripped")

    for vector in corpus["identity_vectors"]:
        if vector["kind"] == "redirect":
            require(vector["expected_document_id"] == vector["requested_url"], "redirect changed document identity")
            require(vector["expected_effective_url"] == vector["effective_url"], "effective redirect URL differs")
        elif vector["kind"] == "conflicting_canonical_hints":
            require(vector["expected_document_ids"] == vector["document_ids"], "canonical hints merged or changed document ids")
        elif vector["kind"] == "same_content_distinct_urls":
            first, second = vector["document_ids"]
            by_fixture_id = {document["id"]: document for document in corpus["documents"]}
            require(first != second and vector["expected_distinct_document_ids"], "same-content identities are not distinct")
            require(
                by_fixture_id[first]["content_sha256"] == by_fixture_id[second]["content_sha256"],
                "same-content identity example does not have equal fingerprints",
            )
        else:
            raise ValueError(f"unknown identity vector: {vector['kind']}")

    for vector in corpus["redirect_vectors"]:
        require(vector["expected_document_id"] == vector["requested_url"], f"redirect changed identity: {vector['id']}")
        if vector["id"] == "redirect_hop_limit":
            require(len(vector["hops"]) > EXPECTED_LIMITS["redirect_hops"], "redirect limit vector is not over the cap")
            require(vector["expected_outcome"] == "reject_over_limit_retain_previous", "redirect limit outcome changed")
        elif vector["id"] == "redirect_loop":
            require(vector["expected_outcome"] == "reject_loop_retain_previous", "redirect loop outcome changed")
        elif vector["id"] == "redirect_to_unadmitted_origin":
            require(vector["expected_outcome"] == "deny_target_retain_previous", "redirect admission outcome changed")
        elif vector["id"] == "relative_permanent_redirect":
            require(len(vector["hops"]) == 1 and vector["hops"][0]["status"] == 301, "relative permanent redirect vector changed")
            require(vector["expected_effective_url"] == vector["terminal_url"], "redirect terminal URL differs")
        else:
            raise ValueError(f"unknown redirect vector: {vector['id']}")

    for vector in corpus["admission_vectors"]:
        require(admission_outcome(vector) == vector["expected"], f"admission outcome differs for {vector['source']}")

    removal_ids = [vector["id"] for vector in corpus["removal_vectors"]]
    require(len(removal_ids) == len(set(removal_ids)), "duplicate removal vector id")
    removal_by_id = {vector["id"]: vector for vector in corpus["removal_vectors"]}
    require(
        set(EXPECTED_REMOVAL_GOLDENS).issubset(removal_by_id),
        "required independent removal cases are missing",
    )
    for vector in corpus["removal_vectors"]:
        visible, enqueue_links, count = removal_outcome(vector)
        require(visible == vector["expected_visible"], f"removal visibility differs for {vector['id']}")
        if "expected_enqueue_links" in vector:
            require(enqueue_links == vector["expected_enqueue_links"], f"nofollow link behavior differs for {vector['id']}")
        if "expected_404_count" in vector:
            require(count == vector["expected_404_count"], f"404 counter differs for {vector['id']}")
        if vector["id"] in EXPECTED_REMOVAL_GOLDENS:
            expected = EXPECTED_REMOVAL_GOLDENS[vector["id"]]
            recorded = (vector["expected_visible"], vector["expected_enqueue_links"], vector.get("expected_404_count", 0))
            require(recorded == expected, f"independent removal expectation differs for {vector['id']}")
            require((visible, enqueue_links, count) == expected, f"independent removal outcome differs for {vector['id']}")

    for vector in corpus["analyzer_vectors"]:
        normalized, tokens = tokenize_example(vector["input"])
        require(normalized == vector["normalized"], f"Unicode normalization/case-fold vector differs: {vector['input']!r}")
        require(tokens == vector["tokens"], f"Unicode token vector differs: {vector['input']!r}")

    extractor_id = corpus["contract"]["extractor_id"]
    analyzer_id = corpus["contract"]["analyzer_id"]
    documents = corpus["documents"]
    ids = [document["id"] for document in documents]
    require(len(ids) == len(set(ids)), "duplicate document id")
    for document in documents:
        require(document["id"].startswith("https://example.test/"), f"unexpected fixture document id: {document['id']}")
        for field in ("title", "body"):
            _, tokens = tokenize_example(document[field])
            require(tokens == document[f"{field}_tokens"], f"stored {field} tokens differ for {document['id']}")
            require(len(tokens) <= EXPECTED_LIMITS["document_tokens"], f"document token limit exceeded: {document['id']}")
            require(all(len(token) <= EXPECTED_LIMITS["token_codepoints"] for token in tokens), f"token limit exceeded: {document['id']}")
        content_hash, version_hash = document_hashes(document["title"], document["body"], extractor_id, analyzer_id)
        require(content_hash == document["content_sha256"], f"content fingerprint differs for {document['id']}")
        require(version_hash == document["version_sha256"], f"document version differs for {document['id']}")

    extraction_vectors = {vector["id"]: vector for vector in corpus["extraction_vectors"]}
    require(
        len(extraction_vectors) == len(corpus["extraction_vectors"])
        and set(extraction_vectors) == set(EXPECTED_EXTRACTION),
        "extraction golden set differs from the finite verifier cases",
    )
    for vector in extraction_vectors.values():
        require(vector["effective_url"].startswith("https://"), f"invalid extraction fixture URL: {vector['id']}")
        if vector["id"] == "html5-fields-and-link-base":
            require("<script>Injected words</script>" in vector["html"], "extraction fixture lost its script exclusion case")
            require("<template>Template words</template>" in vector["html"], "extraction fixture lost its template exclusion case")
        expected = EXPECTED_EXTRACTION[vector["id"]]
        actual = {field: vector[field] for field in ("title", "body", "links")}
        require(actual == expected, f"extraction golden differs for {vector['id']}")

    queries = {query["id"]: query for query in corpus["queries"]}
    require(
        len(queries) == len(corpus["queries"]) and set(queries) == set(EXPECTED_AST),
        "query vector ids differ from the finite verifier cases",
    )
    by_id = {document["id"]: document for document in documents}
    for query_id, query in queries.items():
        require(query["ast"] == EXPECTED_AST[query_id], f"AST changed for {query_id}")
        if query_id in {"unicode_full_case_fold", "unicode_composed_query", "unicode_decomposed_query", "accent_preserved"}:
            _, analyzed = tokenize_example(query["expression"])
            require(analyzed == [query["ast"]["term"]], f"Unicode query analysis differs for {query_id}")
        if query_id == "unicode_single_token_phrase":
            _, analyzed = tokenize_example(query["expression"][1:-1])
            require(query["ast"] == {"phrase": analyzed}, "Unicode phrase analysis differs")
        observed = sorted(
            (document["id"] for document in documents if finite_match(document, query["match_case"])),
            key=lambda value: value.encode("utf-8"),
        )
        require(observed == query["expected_matches"], f"match set differs for {query_id}")
        require(all(document_id in by_id for document_id in query["expected_matches"]), f"unknown match id in {query_id}")

    error_vectors = {vector["expression"]: vector["error"] for vector in corpus["query_errors"]}
    require(
        len(error_vectors) == len(corpus["query_errors"]) and error_vectors == EXPECTED_ERRORS,
        "query error vectors differ from the accepted finite cases",
    )

    ranking_vectors = {vector["query_id"]: vector for vector in corpus["ranking_vectors"]}
    require(
        len(ranking_vectors) == len(corpus["ranking_vectors"])
        and set(ranking_vectors) == {"alpha_term", "shared_exact_tie", "operator_precedence"},
        "ranking vector set changed",
    )
    for query_id, vector in ranking_vectors.items():
        query = queries[query_id]
        terms = vector["terms"]
        stats = corpus_stats(documents, terms)
        expected_stats = vector["expected_stats"]
        require(stats["N"] == expected_stats["N"], f"N differs for {query_id}")
        for field in ("title", "body"):
            near(stats[field]["avg_length"], expected_stats[field]["avg_length"], f"{query_id} {field} average length")
            require(stats[field]["df"] == expected_stats[field]["df"], f"{query_id} {field} df differs")
        scores = {document_id: bm25_score(by_id[document_id], documents, terms) for document_id in query["expected_matches"]}
        require(set(scores) == set(vector["expected_scores"]), f"scored documents differ for {query_id}")
        for document_id, score in scores.items():
            near(score, vector["expected_scores"][document_id], f"{query_id} score for {document_id}")
        for document_id, expected_components in vector.get("expected_components", {}).items():
            require(document_id in by_id, f"unknown component document for {query_id}: {document_id}")
            actual_components = bm25_components(by_id[document_id], documents, terms)
            require(set(expected_components) <= set(actual_components), f"unknown component term for {query_id}")
            for term, fields in expected_components.items():
                for field, expected_component in fields.items():
                    require(field in {"title", "body"}, f"unknown score field {field} for {query_id}")
                    near(actual_components[term][field], expected_component, f"{query_id} {document_id} {term}/{field}")
        order = sorted(scores, key=lambda document_id: (-scores[document_id], document_id.encode("utf-8")))
        require(order == vector["expected_order"], f"ranking order differs for {query_id}")
    require(
        ranking_vectors["shared_exact_tie"]["expected_scores"]["https://example.test/tie-a"]
        == ranking_vectors["shared_exact_tie"]["expected_scores"]["https://example.test/tie-z"],
        "tie fixture scores are not exactly equal",
    )
    duplicate = queries["duplicate_terms"]
    require(duplicate["score_terms"] == ["alpha"], "duplicate query terms must contribute once to score")
    require(duplicate["expected_matches"] == queries["alpha_term"]["expected_matches"], "duplicate AND match set differs")

    verify_lifecycle(corpus["lifecycle"])

    license_text = (ROOT / "fixtures" / "LICENSE.txt").read_text(encoding="utf-8")
    require("CC0 1.0 Universal" in license_text and "reference-v1.json" in license_text, "fixture data license notice is incomplete")

    print(
        f"verified {len(documents)} synthetic documents, {len(corpus['url_vectors'])} URL vectors, "
        f"{len(corpus['redirect_vectors'])} redirect vectors, {len(corpus['removal_vectors'])} removal-policy vectors, "
        f"{len(corpus['analyzer_vectors'])} analyzer vectors, {len(queries)} query cases, "
        f"and {len(ranking_vectors)} BM25 rankings; host Unicode data {unicodedata.unidata_version}"
    )


if __name__ == "__main__":
    try:
        verify()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"reference corpus verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
