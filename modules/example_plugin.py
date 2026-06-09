PLUGIN_NAME = "example_plugin"

def register(engine=None):
    import logging
    logging.info("[Plugin] %s registered", PLUGIN_NAME)
