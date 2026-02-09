import guloader_v5excepts_resolve_constants
import guloader_v5excepts_resolve_exception_jumps
import guloader_v5excepts_resolve_exception_jumps_smart
import guloader_v5excepts_util
import guloader_v5excepts_patterns
from ida_defines import *

def dowork():

    # Resolve obfuscated constants
    guloader_v5excepts_resolve_constants.resolve_obfuscated_constants()

    # Clean undefined
    guloader_v5excepts_util.clean_undefined()

    # Resolve exception jumps C0000005
    guloader_v5excepts_resolve_exception_jumps.resolve_exception_jumps_common(guloader_v5excepts_patterns.patterns_C0000005(), guloader_v5excepts_patterns.prechecks_C0000005)

    # Resolve exception jumps 80000004
    guloader_v5excepts_resolve_exception_jumps.resolve_exception_jumps_common(guloader_v5excepts_patterns.patterns_80000004(), guloader_v5excepts_patterns.prechecks_80000004)

    # Resolve exception jumps C0000096
    guloader_v5excepts_resolve_exception_jumps.resolve_exception_jumps_common(guloader_v5excepts_patterns.patterns_C0000096(), guloader_v5excepts_patterns.prechecks_C0000096)

    # Resolve exception jumps 80000003
    # DISABLED     guloader_v5excepts_resolve_exception_jumps.resolve_exception_jumps_common(guloader_v5excepts_patterns.patterns_80000003(), guloader_v5excepts_patterns.prechecks_80000003)
    # Resolve exception jumps 80000003_only_comment
    # DISABLED     guloader_v5excepts_resolve_exception_jumps.resolve_exception_jumps_common(guloader_v5excepts_patterns.patterns_80000003_only_comment(), guloader_v5excepts_patterns.prechecks_80000003)

    guloader_v5excepts_resolve_exception_jumps_smart.resolve_exception_jumps_smart()

dowork()