from app.ml.llm_patcher import _get_language, build_patch_prompt


def test_build_patch_prompt_complete_data():
    finding = {
        "description": "XSS vulnerability",
        "metadata": {"cwe": "CWE-79"},
        "location": {"path": "src/components/App.tsx"},
    }
    prompt = build_patch_prompt(finding, "<div>{userInput}</div>")

    assert "Description: XSS vulnerability" in prompt
    assert "CWE Identifier: CWE-79" in prompt
    assert "File Path: src/components/App.tsx" in prompt
    assert "Programming Language: TypeScript (React)" in prompt
    assert "<context>\n<div>{userInput}</div>\n</context>" in prompt


def test_build_patch_prompt_missing_and_none_data():
    finding = {"description": None, "metadata": None, "location": None}
    prompt = build_patch_prompt(finding, "some code")

    assert "Description: No description provided." in prompt
    assert "CWE Identifier: Unknown CWE" in prompt
    assert "File Path: unknown_file" in prompt
    assert "Programming Language: Unknown" in prompt


def test_get_language():
    assert _get_language("server.py") == "Python"
    assert _get_language("index.ts") == "TypeScript"
    assert _get_language("Makefile") == "Unknown"
