"""toll-fraud-guard: detect toll fraud on a hosted PBX, and contain it with a human in the loop.

Detection (registrations.py, calls.py, state.py) only reads. Containment
(contain/) changes the live PBX, and only after a preview, an explicit yes, and
a one-time code delivered to the person asking. bridge.py turns findings into
proposals; it never acts on them.
"""

__version__ = "0.1.0"
