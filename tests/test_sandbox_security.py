"""Regression tests for the 2026-11-15 server-side template injection (SSTI) incident.

Templates are attacker-controlled input; the render environment must be sandboxed.
"""
import pytest
from jinja2 import Undefined
from jinja2.sandbox import SecurityError

import main

PAYLOADS = [
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ lipsum.__globals__['os'].popen('id').read() }}",
    "{{ config.__class__.__init__.__globals__ }}",
    "{{ joiner.__init__.__globals__ }}",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_template_cannot_reach_os(payload):
    env = main.build_jinja_env(Undefined)
    with pytest.raises(SecurityError):
        env.from_string(payload).render()


def test_env_is_sandboxed_type():
    from jinja2.sandbox import ImmutableSandboxedEnvironment
    assert isinstance(main.build_jinja_env(Undefined), ImmutableSandboxedEnvironment)


def test_normal_templates_still_render():
    env = main.build_jinja_env(Undefined)
    out = env.from_string("{% for p in people %}{{ p.name|upper }}, {% endfor %}{{ n + 1 }}").render(
        people=[{"name": "ada"}, {"name": "bob"}], n=1)
    assert out == "ADA, BOB, 2"


def test_linter_env_is_sandboxed():
    from services.docx_linter import DocxJinjaLinterService
    from jinja2.sandbox import ImmutableSandboxedEnvironment
    assert isinstance(DocxJinjaLinterService().env, ImmutableSandboxedEnvironment)
