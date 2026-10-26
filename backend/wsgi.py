"""Production entry point: `waitress-serve --listen=127.0.0.1:5050 --threads=32 wsgi:app`.

Run a single process. Background jobs (syslog listener, host agent, performance sampler)
start inside create_app and must not run twice.
"""

import logging

from siem import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
