import json
from parser.masking import to_masked_dict


def log_request(parsed_request):

    with open("alerts.log", "a") as logfile:

        logfile.write(
            json.dumps(to_masked_dict(parsed_request), indent=4)
        )

        logfile.write("\n")
        logfile.write("-" * 60)
        logfile.write("\n")