import logging

from siem import create_app
from siem.config import Config

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = Config()
    app = create_app(config)
    print(f"Starting SIEM backend on http://{config.HOST}:{config.PORT} ...")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
