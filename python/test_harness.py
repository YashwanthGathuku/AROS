from aros_research.harnesses import GrokBuildHarness, NativeHarness


def test_native_harness_name() -> None:
    assert NativeHarness.name == "native"


def test_grok_plan_never_auto_approves() -> None:
    argv = GrokBuildHarness().plan_argv("summarize the surface", "/tmp/target")
    assert argv[0] == "grok"
    assert "--always-approve" not in argv
    assert "--disable-web-search" in argv
    assert "--cwd" in argv
