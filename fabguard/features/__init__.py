"""
Collector features.

One module per feature. The module name is the feature name used in
config.ENABLED_FEATURES. Each defines exactly one Feature subclass and ends
with a __main__ block so it can be run on its own:

    python3 -m fabguard.features.<name>
"""
