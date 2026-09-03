from routelint.loader import build_ctx


def check_one(rule, config: dict):
    return rule.check(build_ctx(config))


def codes(findings):
    return [f.code for f in findings]

