from clefcve.clef import QUESTIONS_DIR, load_pack, question_hash


def test_all_packs_load_and_fit_api_limits():
    for path in QUESTIONS_DIR.rglob("*.yaml"):
        pack = load_pack(str(path))
        assert pack["pack"] == path.stem
        assert 1 <= len(pack["questions"]) <= 64
        for qid, q in pack["questions"].items():
            assert q["type"] in {"choice", "noul", "score"}, qid
            assert q["instructions"], qid
            crit = q["criteria"]
            if q["type"] == "noul":
                assert set(crit) == {"true", "false"}, qid  # YAML booleans normalized to strings
            else:
                assert 2 <= len(crit) <= 26, qid


def test_question_hash_changes_with_wording():
    q = {"type": "noul", "instructions": "a", "criteria": {"true": "x", "false": "y"}}
    assert question_hash(q) == question_hash(dict(q))
    assert question_hash(q) != question_hash({**q, "instructions": "b"})


def test_unquoted_yaml_booleans_become_strings(tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("pack: t\nstate: description_only\nquestions:\n  q:\n    type: noul\n    instructions: i\n"
                 "    criteria:\n      false: no\n      true: yes\n")
    assert set(load_pack(str(p))["questions"]["q"]["criteria"]) == {"true", "false"}
