from backend.core.cancellation import CancelToken
from backend.engines.base import EngineContext
from backend.engines.docker import DockerfileEngine, parse_instructions
from backend.engines.inventory import build_inventory


def _rules(make_tree, settings, dockerfile):
    root = make_tree({"Dockerfile": dockerfile})
    inventory = build_inventory(root, settings.max_scan_file_bytes)
    findings = DockerfileEngine().run(EngineContext(root=root, inventory=inventory, settings=settings,
                                                    token=CancelToken())).findings
    return sorted(f.rule_id for f in findings)


def test_parse_instructions_joins_continuations():
    instructions = parse_instructions("FROM a\n# comment\nRUN apt-get update && \\\n    apt-get install -y curl\n")
    assert [(i.line, i.text) for i in instructions] == [
        (1, "FROM a"),
        (3, "RUN apt-get update &&  apt-get install -y curl"),
    ]


def test_hardened_dockerfile_is_clean(make_tree, settings):
    dockerfile = (
        "FROM python:3.12-slim AS build\n"
        "RUN pip install --no-cache-dir build\n"
        "FROM build\n"
        "RUN useradd --system app\n"
        "USER app\n"
        'CMD ["python", "app.py"]\n'
    )
    assert _rules(make_tree, settings, dockerfile) == []


def test_insecure_dockerfile(make_tree, settings):
    dockerfile = (
        "FROM ubuntu\n"
        "RUN curl -fsSL https://get.example.sh | sh\n"
        "ENV DB_PASSWORD=SuperSecretValue\n"
        "ADD https://example.com/tool.tgz /opt/\n"
        "RUN chmod -R 777 /app && sudo apt-get install -y x\n"
        "RUN wget --no-check-certificate https://x/y\n"
        "EXPOSE 22 8080\n"
        "USER root\n"
    )
    assert _rules(make_tree, settings, dockerfile) == [
        "DOCKER001", "DOCKER002", "DOCKER003", "DOCKER004", "DOCKER005", "DOCKER006", "DOCKER007",
        "DOCKER008", "DOCKER009",
    ]


def test_base_image_pinning_rules(make_tree, settings):
    assert "DOCKER002" in _rules(make_tree, settings, "FROM node:latest\nUSER node\n")
    assert "DOCKER002" not in _rules(make_tree, settings, "FROM scratch\nUSER 1000\n")
    assert "DOCKER002" not in _rules(make_tree, settings, "ARG BASE\nFROM ${BASE}\nUSER app\n")
    assert "DOCKER002" not in _rules(make_tree, settings, "FROM alpine@sha256:abc123\nUSER app\n")
    assert "DOCKER002" not in _rules(make_tree, settings, "FROM registry.local:5000/app:1.2\nUSER app\n")


def test_user_only_in_an_earlier_stage_still_runs_as_root(make_tree, settings):
    dockerfile = "FROM node:20 AS build\nUSER node\nFROM node:20-slim\nCMD node app.js\n"
    assert "DOCKER001" in _rules(make_tree, settings, dockerfile)
