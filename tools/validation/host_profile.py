"""Replace only the profile action in an isolated host-lab helper."""
import re


def replace_profile_branch(source, replacement):
    starts = list(re.finditer(r"(?m)^elif act\s*==\s*(['\"])profile\1\s*:", source))
    if len(starts) != 1:
        raise ValueError("expected exactly one profile action")
    start = starts[0]
    following = re.search(r"(?m)^(?:elif|else)\b", source[start.end():])
    if following is None:
        raise ValueError("profile action has no following branch boundary")
    end = start.end() + following.start()
    updated = source[:start.start()] + replacement.rstrip() + "\n" + source[end:]
    compile(updated, "<host-lab-helper>", "exec")
    return updated
