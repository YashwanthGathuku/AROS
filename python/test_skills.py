from aros_research.models.openai_compat import OpenAICompatConfig, OpenAICompatProvider
from aros_research.skills.catalog import SKILLS, skill_ids
from pydantic import SecretStr


def test_all_required_skills_are_seeded() -> None:
    required = {
        "breadth_depth_context",
        "reachability_boundary_mapping",
        "trust_boundary_mapping",
        "source_to_sink",
        "sink_to_source",
        "assumption_attack",
        "parser_interpretation_disagreement",
        "representation_transformation_analysis",
        "hidden_component_inference",
        "fast_falsification",
        "differential_experiment",
        "negative_control_design",
        "anomaly_investigation",
        "primitive_composition",
        "attack_chain_reasoning",
        "patch_archaeology",
        "variant_analysis",
        "incomplete_fix_search",
        "discovery_cascade",
        "missed_bug_analysis",
    }
    assert required <= set(skill_ids())
    for skill in SKILLS:
        for key in (
            "id",
            "description",
            "applicability",
            "required_facts",
            "hypothesis_templates",
            "experiment_strategy",
            "negative_controls",
            "evidence_contract",
            "known_failure_modes",
            "relevant_pattern_families",
            "recommended_tool_categories",
            "estimated_cost_class",
            "safety_requirements",
            "provenance",
        ):
            assert key in skill


def test_api_key_is_redacted() -> None:
    cfg = OpenAICompatConfig(
        base_url="http://127.0.0.1:8080/v1",
        model="local",
        api_key=SecretStr("sk-secret"),
    )
    dumped = OpenAICompatProvider(cfg).redacted()
    assert dumped["api_key"] == "***"
    assert "sk-secret" not in str(dumped)
