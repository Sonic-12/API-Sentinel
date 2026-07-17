from dataclasses import asdict
import json


def log_request(parsed_request):

    with open("alerts.log", "a") as logfile:

        logfile.write(
            json.dumps(asdict(parsed_request), indent=4)
        )

        logfile.write("\n")
        logfile.write("-" * 60)
        logfile.write("\n")