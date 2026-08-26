from aros_research.agents.director import ResearchDirector
from aros_research.domain import ToolCapability
from aros_research.worker import _absolute_path


def test_director_plans_multi_turn_campaign() -> None:
    director = ResearchDirector()
    intents = director.plan_campaign_intents(
        "/tmp/target",
        search_needle="VULN_",
        read_path="/tmp/target/server.py",
        http_host="127.0.0.1",
        http_port=18080,
    )
    caps = [i.capability for i in intents]
    assert caps == [
        ToolCapability.list_tree,
        ToolCapability.search_text,
        ToolCapability.read_file,
        ToolCapability.http_request,
    ]
    assert intents[0].path == "/tmp/target"
    assert intents[-1].host == "127.0.0.1"
    assert intents[-1].port == 18080


def test_director_omits_optional_intents() -> None:
    intents = ResearchDirector().plan_campaign_intents("/lab")
    assert [i.capability for i in intents] == [
        ToolCapability.list_tree,
        ToolCapability.search_text,
    ]


def test_posix_absolute_path_is_not_rewritten() -> None:
    assert _absolute_path("/var/run/docker.sock") == "/var/run/docker.sock"
