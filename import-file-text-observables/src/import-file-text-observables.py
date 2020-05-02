# coding: utf-8
import os
import yaml
import time
import uuid
import json
import re
from pycti import OpenCTIConnectorHelper, get_config_variable

class ImportFileTextObservables:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.create_indicator = get_config_variable(
            "TEXT_OBSERVABLES_CREATE_INDICATOR",
            ["text_observables", "create_indicator"],
            config,
        )

    def _process_message(self, data):
        old_token = self.helper.api.get_token()
        token = None
        if "token" in data:
            token = data["token"]
        file_path = data["file_path"]
        file_name = os.path.basename(file_path)
        work_context = data["work_context"]
        file_uri = self.helper.opencti_url + file_path
        self.helper.log_info("Importing the file " + file_uri)
        # Get the file
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        # Write the file
        path = "/tmp/" + file_name
        f = open(path, "wb")
        f.write(file_content)
        f.close()

        # Parse
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.0",
            "objects": [],
        }
        observed_data = {
            "id": "observed-data--" + str(uuid.uuid4()),
            "type": "observed-data",
            "x_opencti_indicator_create": self.create_indicator,
            "objects": {},
        }
        i = 0
        with open(path) as f:
            for ioc in f:
                resolved_match = self.resolve_match(ioc)
                if resolved_match:
                    observable = {
                        "type": resolved_match["type"],
                        "x_opencti_observable_type": resolved_match[
                            "type"
                        ],
                        "x_opencti_observable_value": resolved_match[
                            "value"
                        ],
                        "x_opencti_indicator_create": self.create_indicator,
                    }
                    observed_data["objects"][i] = observable
                    print(observed_data["objects"][i])
                    i += 1

        # Get Context
        if len(observed_data["objects"]) > 0:
            bundle["objects"].append(observed_data)
            if work_context is not None and len(work_context) > 0:
                report = self.helper.api.report.read(id=work_context)
                if report is not None:
                    report_stix = {
                        "type": "report",
                        "id": report["stix_id_key"],
                        "name": report["name"],
                        "description": report["description"],
                        "published": self.helper.api.stix2.format_date(
                            report["published"]
                        ),
                        "object_refs": [],
                    }
                    report_stix["object_refs"].append(observed_data["id"])
                    bundle["objects"].append(report_stix)
            if token:
                self.helper.api.set_token(token)
            bundles_sent = self.helper.send_stix2_bundle(
                json.dumps(bundle), None, False, False
            )
            self.helper.api.set_token(old_token)
            return [
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            ]

    def start(self):
        self.helper.listen(self._process_message)

    def resolve_match(self, ioc):
        # Regex for detection
        regex_url = re.compile(
            '([A-Za-z]+://)([-\w]+(?:\.\w[-\w]*)+)(:\d+)?(/[^.!,?\"<>\[\]{}\s\x7F-\xFF]*(?:[.!,?]+[^.!,?\"<>\[\]{}\s\x7F-\xFF]+)*)?')
        regex_domain = re.compile('\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b')
        regex_ipv4 = re.compile(
            '(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?')
        regex_ipv6 = re.compile(
            '((?=.*::)(?!.*::.+::)(::)?([\dA-Fa-f]{1,4}:(:|\b)|){5}|([\dA-Fa-f]{1,4}:){6})((([\dA-Fa-f]{1,4}((?!\3)::|:\b|(?![\dA-Fa-f])))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})')
        regex_md5 = re.compile('^[a-fA-F0-9]{32}$')
        regex_sha1 = re.compile('^[a-fA-F0-9]{40}$')
        regex_sha256 = re.compile('^[A-Fa-f0-9]{64}$')

        # Regex the IOC if the line starts with '#' , ignore it.
        if ioc.startswith('#') is False:
            if regex_url.match(ioc):
                ioc_type = 'URL'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_domain.match(ioc):
                ioc_type = 'Domain'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_ipv4.match(ioc):
                ioc_type = 'IPv4-Addr'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_ipv6.match(ioc):
                ioc_type = 'IPv6-Addr'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_sha256.match(ioc):
                ioc_type = 'File-SHA256'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_sha1.match(ioc):
                ioc_type = 'File-SHA1'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            elif regex_md5.match(ioc):
                ioc_type = 'File-MD5'
                return {"type": ioc_type, "value": ioc.rstrip('\n')}
            else:
                print(ioc + ' - NO MATCH')
                return False
        else:
            return False

if __name__ == "__main__":
    try:
        connectorImportFileTextObservables = ImportFileTextObservables()
        connectorImportFileTextObservables.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)


