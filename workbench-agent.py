#!/usr/bin/env python3

# Copyright: FossID AB 2022

import json
import time
import logging
import argparse
import random
import base64
import os
import subprocess
from argparse import RawTextHelpFormatter
import sys
import traceback
import requests

# from dotenv import load_dotenv
logger = logging.getLogger("log")


class Workbench:
    def __init__(self, api_url: str, api_user: str, api_token: str):
        self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token

    # @staticmethod
    # def _get_env_var_or_raise(var_name: str):
    #     if var_name not in os.environ.keys() or os.environ[var_name] == "":
    #         raise Exception("{} is not set".format(var_name))
    #     return os.environ[var_name]

    # Generic function for sending requests to API
    # payload (dict):   payload of the JSON request
    def _send_request(self, payload: dict) -> dict:
        url = self.api_url
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
            # "X-Requested-With": "XMLHttpRequest",
            # "Origin": "http://localhost:2880",
            # "Connection": "keep-alive",
        }
        req_body = json.dumps(payload)
        logger.debug("url %s", url)
        logger.debug("url %s", headers)
        logger.debug(req_body)
        response = requests.request(
            "POST", url, headers=headers, data=req_body, timeout=1800
        )
        logger.debug(response.text)
        return json.loads(response.text)

    # Upload .fossid file using API Upload endpoint
    # scan_code(str):  Code of the scan where the hashes should be uploaded
    # path(str): Path to blind scan result ( .fossid file)
    def upload_files(self, scan_code: str, path: str):
        name = base64.b64encode(os.path.basename(path).encode()).decode("utf-8")
        scan_code = base64.b64encode(scan_code.encode()).decode("utf-8")
        headers = {"FOSSID-SCAN-CODE": scan_code, "FOSSID-FILE-NAME": name}
        try:
            with open(path, "rb") as file:
                resp = requests.post(
                    self.api_url,
                    headers=headers,
                    data=file,
                    auth=(self.api_user, self.api_token),
                    timeout=1800,
                )
                try:
                    resp.json()
                except:
                    print(f"Failed to decode json {resp.text}")
                    print(traceback.print_exc())
                    sys.exit(1)
        except IOError:
            # Error opening file
            print(f"Failed to upload hashes for scan {scan_code}")
            print(traceback.print_exc())
            sys.exit(1)

    def _delete_existing_scan(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "delete",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "delete_identifications": "true",
            },
        }
        return self._send_request(payload)

    def create_webapp_scan(self, scan_code: str, project_code: str = None) -> bool:
        payload = {
            "group": "scans",
            "action": "create",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "scan_name": scan_code,
                "project_code": project_code,
                "description": "Automatically created scan by Workbench Agent script.",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise Exception("Failed to create scan {}: {}".format(scan_code, response))
        if "error" in response.keys():
            raise Exception(
                "Failed to create scan {}: {}".format(scan_code, response["error"])
            )
        return response["data"]["scan_id"]

    # def _download_content_from_git(self, scan_code: str):
    #     payload = {
    #         "group": "scans",
    #         "action": "download_content_from_git",
    #         "data": {
    #             "username": self.api_user,
    #             "key": self.api_token,
    #             "scan_code": scan_code,
    #         },
    #     }
    #     response = self._send_request(payload)
    #     if response["status"] != "1":
    #         message = "Failed to get content from git for scan {}: {}".format(
    #             scan_code, response["error"]
    #         )
    #         raise Exception(message)
    #
    # def _get_git_download_status(self, scan_code: str):
    #     payload = {
    #         "group": "scans",
    #         "action": "check_status_download_content_from_git",
    #         "data": {
    #             "username": self.api_user,
    #             "key": self.api_token,
    #             "scan_code": scan_code,
    #         },
    #     }
    #     return self._send_request(payload)

    def _get_scan_status(self, scan_type: str, scan_code: str):
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "type": scan_type,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise Exception(
                "Failed to retrieve scan status from \
                scan {}: {}".format(
                    scan_code, response["error"]
                )
            )
        return response["data"]

    def start_dependency_analysis(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise Exception(
                "Failed to start dependency analysis scan {}: {}".format(
                    scan_code, response["error"]
                )
            )
    #
    # def _wait_for_git_download(self, scan_code: str):
    #     print("Downloading {}".format(scan_code))
    #
    #     timeout_minutes = SCAN_TIMEOUT_MINUTES
    #     timeout_at = datetime.datetime.now() + datetime.timedelta(
    #         minutes=timeout_minutes
    #     )
    #     git_downloaded = False
    #     while not git_downloaded:
    #         response = self._get_git_download_status()
    #
    #         if response["data"] == "FINISHED":
    #             git_downloaded = True
    #
    #         if "fatal" in response.keys():
    #             raise Exception(
    #                 "Failed to retrieve git pull status from \
    #                 scan {}: {}".format(
    #                     scan_code, response["fatal"]
    #                 )
    #             )
    #
    #         if "error" in response.keys():
    #             raise Exception(
    #                 "Failed to retrieve git pull status from \
    #                 scan {}: {}".format(
    #                     scan_code, response["error"]
    #                 )
    #             )
    #
    #         time.sleep(5)
    #         if datetime.datetime.now() > timeout_at:
    #             print("git download timeout {}".format(scan_code))
    #             raise Exception("git download timeout")
    #         if (
    #                 "message" in response.keys()
    #                 and "Git download failed" in response["message"]
    #         ):
    #             raise Exception(response["message"])

    def wait_for_scan_to_finish(
            self,
            scan_type: str,
            scan_code: str,
            scan_number_of_tries: int,
            scan_wait_time: int,
    ):
        # pylint: disable-next=unused-variable
        for x in range(scan_number_of_tries):
            scan_status = self._get_scan_status(scan_type, scan_code)
            is_finished = (
                    scan_status["is_finished"]
                    or scan_status["is_finished"] == "1"
                    or scan_status["status"] == "FAILED"
                    or scan_status["status"] == "FINISHED"
            )
            if is_finished:
                if (
                        scan_status["percentage_done"] == "100%"
                        or scan_status["percentage_done"] == 100
                        or (
                            scan_type == 'DEPENDENCY_ANALYSIS'
                            and
                            (scan_status["percentage_done"] == "0%" or scan_status["percentage_done"] == "0%%")
                         )
                ):
                    print(
                        "Scan percentage_done = 100%, scan has finished. Status: {}".format(
                            scan_status["status"]
                        )
                    )
                    return True
                raise Exception(
                    "Scan finished with status: {}  percentage: {} ".format(
                        scan_status["status"], scan_status["percentage_done"]
                    )
                )
            # If scan did not finished, print info about progress
            print(
                "Scan {} is running. Percentage done: {}%  Status: {}".format(
                    scan_code, scan_status["percentage_done"], scan_status["status"]
                )
            )
            # Wait given time
            time.sleep(scan_wait_time)
        # If this code is reached it means the scan didn't finished after  scan_number_of_tries X scan_wait_time
        print("{} timeout: {}".format(scan_type, scan_code))
        raise Exception("scan timeout")

    def _get_pending_files(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        # all other situations
        raise Exception(
            "Error getting pending files \
            result: {}".format(
                response
            )
        )

    def projects_get_policy_warnings_info(self, project_code: str):
        payload = {
            "group": "projects",
            "action": "get_policy_warnings_info",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise Exception(
            "Error getting project policy warnings information \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_components(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise Exception(
            "Error getting identified components \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_licenses(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "unique": "1",
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise Exception(
            "Error getting identified licenses \
            result: {}".format(
                response
            )
        )

    def _get_dependency_analysis_result(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]

        raise Exception(
            "Error getting dependency analysis \
            result: {}".format(
                response
            )
        )

    def _cancel_scan(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "cancel_run",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise Exception("Error cancelling scan: {}".format(response))

    def _assert_scan_can_start(self, scan_code: str):
        scan_status = self._get_scan_status("SCAN", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise Exception(
                "Cannot start scan. Current status of the scan is {}.".format(
                    scan_status["status"]
                )
            )

    def assert_dependency_analysis_can_start(self, scan_code: str):
        scan_status = self._get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise Exception(
                "Cannot start dependency analysis. Current status of the scan is {}.".format(
                    scan_status["status"]
                )
            )
    def extract_archives(self, scan_code: str, recursively_extract_archives: bool, jar_file_extraction: bool):
        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "recursively_extract_archives": recursively_extract_archives,
                "jar_file_extraction": jar_file_extraction
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            raise Exception("Call extract_archives returned error: {}".format(response))
        return True

    def check_if_scan_exists(self, scan_code: str):
        payload = {
            "group": "scans",
            "action": "get_information",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1":
            return True
        else:
            return False

    def check_if_project_exists(self, project_code: str):
        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            return False
        # if response["status"] == "0":
        #     raise Exception("Failed to get project status: {}".format(response))
        return True

    def create_project(self, project_code: str):
        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
                "project_name": project_code,
                "description": "Automatically created by Workbench Agent script",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise Exception("Failed to create project: {}".format(response))
        print("Created project {}".format(project_code))

    def run_scan(
            self,
            scan_code: str,
            limit: int,
            sensitivity: int,
            auto_identification_detect_declaration: bool,
            auto_identification_detect_copyright: bool,
            auto_identification_resolve_pending_ids: bool,
            delta_only: bool,
            run_dependency_analysis: bool,
            reuse_identification: bool,
            identification_reuse_type: str = None,
            specific_code: str = None,
    ):
        scan_exists = self.check_if_scan_exists(scan_code)
        if not scan_exists:
            raise Exception(
                "Scan with scan_code: {} doesn't exist when calling 'run' action!".format(
                    scan_code
                )
            )

        self._assert_scan_can_start(scan_code)
        print("Starting scan {}".format(scan_code))
        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                "auto_identification_detect_declaration": int(
                    auto_identification_detect_declaration
                ),
                "auto_identification_detect_copyright": int(
                    auto_identification_detect_copyright
                ),
                "auto_identification_resolve_pending_ids": int(
                    auto_identification_resolve_pending_ids
                ),
                "delta_only": int(delta_only),
            },
        }
        if reuse_identification:
            data = payload["data"]
            data["reuse_identification"] = "1"
            # 'any', 'only_me', 'specific_project', 'specific_scan'
            if identification_reuse_type in {"specific_project", "specific_scan"}:
                data["identification_reuse_type"] = identification_reuse_type
                data["specific_code"] = specific_code
            else:
                data["identification_reuse_type"] = identification_reuse_type

        response = self._send_request(payload)
        if response["status"] != "1":
            logger.error(
                "Failed to start scan {}: {} payload {}".format(
                    scan_code, response, payload
                )
            )
            raise Exception(
                "Failed to start scan {}: {}".format(scan_code, response["error"])
            )
        return response

    # def get_scan_url(self):
    #     return "{}/?action=scanview&sid={}".format(self.host, self.scan_id)


# This class handles calling CLI and generating a .fossid file containing hashes of the scanned files
class CliWrapper:
    # __parameters (dictionary): Dictionary of parameters passed to 'fossid-cli'
    __parameters = {}

    # Args:
    # cli_path (string): Path to the executable file "fossid"
    # config_path (string): Path to the configuration file "fossid.conf"
    # timeout (int): timeout for CLI expressed in seconds
    def __init__(self, cli_path, config_path, timeout="120"):
        self.cli_path = cli_path
        self.config_path = config_path
        self.timeout = timeout

    # Executes  fossid-cli --version
    # Returns string
    def get_version(self):
        args = ["timeout", self.timeout, self.cli_path, "--version"]
        try:
            result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            return (
                    "Calledprocerr: "
                    + str(e.cmd)
                    + " "
                    + str(e.returncode)
                    + " "
                    + str(e.output)
            )
        # pylint: disable-next=broad-except
        except Exception as e:
            return "Error: " + str(e)

        return result

    def blind_scan(self, path):
        temporary_file_path = "/tmp/blind_scan_result_" + self.randstring(8) + ".fossid"
        # Create temporary file, make it empty if already exists
        # pylint: disable-next=consider-using-with,unspecified-encoding
        open(temporary_file_path, "w").close()
        my_cmd = f"timeout {self.timeout} {self.cli_path} --local --enable-sha1=1 {path} > {temporary_file_path}"
        try:
            # pylint: disable-next=unspecified-encoding
            with open(temporary_file_path, "w") as outfile:
                subprocess.check_output(my_cmd, shell=True, stderr=outfile)
            # result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(
                "Calledprocerr: "
                + str(e.cmd)
                + " "
                + str(e.returncode)
                + " "
                + str(e.output)
            )
            print(traceback.format_exc())
            sys.exit()
        # pylint: disable-next=broad-except
        except Exception as e:
            print("Error: " + str(e))
            print(traceback.format_exc())
            sys.exit()

        return temporary_file_path

    # Generate a random string of a given length
    #        Args:
    #            length (int)
    #        Returns
    #            string
    @staticmethod
    def randstring(length=10):
        valid_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join((random.choice(valid_letters) for i in range(0, length)))


def parse_cmdline_args():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Run FossID Workbench Agent",
        formatter_class=RawTextHelpFormatter,
    )
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")

    # Add back help
    optional.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help message and exit",
    )

    required.add_argument(
        "--api_url",
        help="URL of the Workbench API instance, Ex:  https://myserver.com/api.php",
        type=str,
        required=True,
    )
    required.add_argument(
        "--api_user",
        help="Workbench user that will make API calls",
        type=str,
        required=True,
    )
    required.add_argument(
        "--api_token",
        help="Workbench user API token (Not the same with user password!!!)",
        type=str,
        required=True,
    )
    required.add_argument(
        "--project_code",
        help="Name of the project inside Workbench where the scan will be created.\n"
             "If the project doesn't exist, it will be created",
        type=str,
        required=True,
    )
    required.add_argument(
        "--scan_code",
        help="The scan code user when creating the scan in Workbench. It can be based on some env var,\n"
             "for example:  ${BUILD_NUMBER}",
        type=str,
        required=True,
    )
    optional.add_argument(
        "--limit",
        help="Limits CLI results to N most significant matches (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--sensitivity",
        help="Sets snippet sensitivity to a minimum of N lines (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--recursively_extract_archives",
        help="Recursively extract nested archives. Default true.",
        action="store_true",
        default=True,
    )
    optional.add_argument(
        "--jar_file_extraction",
        help="Control default behavior related to extracting jar files. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--blind_scan",
        help="Call CLI and generate file hashes. Upload hashes and initiate blind scan.",
        action="store_true",
        default=False,
    )

    optional.add_argument(
        "--run_dependency_analysis",
        help="Initiate dependency analysis after finishing scanning for matches in KB.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_declaration",
        help="Automatically detect license declaration inside files. This argument expects no value, not passing\n"
             "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_copyright",
        help="Automatically detect copyright statements inside files. This argument expects no value, not passing\n"
             "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_resolve_pending_ids",
        help="Automatically resolve pending identifications. This argument expects no value, not passing\n"
             "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--delta_only",
        help="""Scan only delta (newly added files from last scan).""",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--reuse_identifications",
        help="If present, try to use an existing identification depending on parameter ‘identification_reuse_type‘.",
        action="store_true",
        default=False,
        required=False,
    )
    optional.add_argument(
        "--identification_reuse_type",
        help="Based on reuse type last identification found will be used for files with the same hash.",
        choices=["any", "only_me", "specific_project", "specific_scan"],
        default="any",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--specific_code",
        help="The scan code user when creating the scan in Workbench. It can be based on some env var,\n"
             "for example:  ${BUILD_NUMBER}",
        type=str,
        required=False,
    )
    required.add_argument(
        "--scan_number_of_tries",
        help="""Number of calls to 'check_status' till declaring the scan failed from the point of view of the agent.""",
        type=int,
        default=960,  # This means 8 hours when --scan_wait_time has default value 30 seconds
        required=False,
    )
    required.add_argument(
        "--scan_wait_time",
        help="Time interval between calling 'check_status', expressed in seconds (default 30 seconds)",
        type=int,
        default=30,
        required=False,
    )
    required.add_argument(
        "--path",
        help="Path of the directory where the files to be scanned reside",
        type=str,
        required=True,
    )

    optional.add_argument(
        "--log",
        help="specify logging level. Allowed values: DEBUG, INFO, WARNING, ERROR",
        default="ERROR",
    )

    optional.add_argument(
        "--path-result",
        help='Save results to specified path',
        type=str,
        required=False,
    )

    optional.add_argument(
        "--get_scan_identified_components",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
             "When passing this parameter the agent will return the list of identified components instead.\n"
             "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--projects_get_policy_warnings_info",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
             "When passing this parameter the agent will return information about policy warnings for project,\n"
             "including the warnings counter.\n"
             "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()
    return args


def save_results(params, results):
    if params.path_result:
        if os.path.isdir(params.path_result):
            fname = os.path.join(params.path_result, "wb_results.json")
            try:
                with open(fname, "w") as file:
                    file.write(json.dumps(results, indent=4))
                    print(f"Results saved to: {fname}")
            except Exception:
                logger.debug(f"Error trying to write results to {fname}")
                print(f"Error trying to write results to {fname}")
        elif os.path.isfile(params.path_result):
            fname = params.path_result
            _folder = os.path.dirname(params.path_result)
            _fname = os.path.basename(params.path_result)
            if _fname:
                if not _fname.endswith(".json"):
                    try:
                        extension = _fname.split(".")[-1]
                        _fname = _fname.replace(extension, "json")
                    except (TypeError, IndexError):
                        _fname = f"{_fname.replace('.', '_')}.json"
            else:
                _fname = "wb_results.json"
            try:
                os.makedirs(_folder, exist_ok=True)
                try:
                    with open(fname, "w") as file:
                        file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                except Exception:
                    logger.debug(f"Error trying to write results to {fname}")
            except (IOError, PermissionError):
                logger.debug(f"Error trying to create folder: {_folder}")
        else:
            logger.debug(f"Folder or file does not exist: {params.path_result}")
            try:
                fname = params.path_result
                if fname.endswith(".json"):
                    _folder = os.path.dirname(fname)
                else:
                    if "." in fname:
                        _folder = os.path.dirname(fname)
                    else:
                        _folder = fname
                    fname = os.path.join(_folder, "wb_results.json")
                try:
                    os.makedirs(_folder, exist_ok=True)
                    try:
                        with open(fname, "w") as file:
                            file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                    except Exception:
                        logger.debug(f"Error trying to write results to {fname}")
                except Exception:
                    logger.debug(f"Error trying to create folder: {_folder}")
            except Exception:
                logger.debug(f"Error trying to create report: {params.path_result}")


def main():
    # load_dotenv()
    # Retrieve parameters from command line
    params = parse_cmdline_args()
    logger.setLevel(params.log)
    f_handler = logging.FileHandler("log-agent.txt")
    f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.addHandler(f_handler)

    # Display parsed parameters
    print("Parsed parameters: ")
    for k, v in params.__dict__.items():
        print("{} = {}".format(k, v))

    if params.blind_scan:
        # print(type(params))
        cli_wrapper = CliWrapper("/usr/bin/fossid-cli", "/etc/fossid.conf")
        # Display fossid-cli version just to validate the path to CLI
        print(cli_wrapper.get_version())

        # Run scan and save .fossid file as temporary file
        blind_scan_result_path = cli_wrapper.blind_scan(params.path)
        print(
            "Temporary file containing hashes generated at path: {}".format(
                blind_scan_result_path
            )
        )
        # f = open(blind_scan_result_path, 'r')
        # file_contents = f.read()
        # print(file_contents)
        # f.close()
        # print ("=============================== End of blind file ==========================")

    # Create Project if it doesn't exist
    workbench = Workbench(params.api_url, params.api_user, params.api_token)
    if not workbench.check_if_project_exists(params.project_code):
        workbench.create_project(params.project_code)
    # Create scan if it doesn't exist
    scan_exists = workbench.check_if_scan_exists(params.scan_code)
    if not scan_exists:
        print(
            f"Scan with code {params.scan_code} does not exist. Calling API to create it..."
        )
        workbench.create_webapp_scan(params.scan_code, params.project_code)
    else:
        print(
            f"Scan with code {params.scan_code} already exists. Proceeding to uploading hashes..."
        )
    # Handle blind scan differently from regular scan
    if params.blind_scan:
        # Upload temporary file with blind scan hashes
        print("Parsed path: ", params.path)
        workbench.upload_files(params.scan_code, blind_scan_result_path)

        # delete .fossid file containing hashes (after upload to scan)
        if os.path.isfile(blind_scan_result_path):
            os.remove(blind_scan_result_path)
        else:
            print(
                "Can not delete the file {} as it doesn't exists".format(
                    blind_scan_result_path
                )
            )
    # Handle normal scanning (directly uploading files at given path instead of generating hashes with CLI)
    else:
        if not os.path.isdir(params.path):
            # The given path is an actual file path. Only this file will be uploaded
            print("Uploading file indicated in --path parameter: {}".format(params.path))
            workbench.upload_files(params.scan_code, params.path)
        else:
            # Get all files found at given path (including in subdirectories). Exclude directories
            print("Uploading files found in directory indicated in --path parameter: {}".format(params.path))
            counter_files = 0
            for root, directories, filenames in os.walk(params.path):
                for filename in filenames:
                    if not os.path.isdir(os.path.join(root, filename)):
                        counter_files = counter_files + 1
                        workbench.upload_files(params.scan_code, os.path.join(root, filename))
            print("A total of {} files uploaded".format(counter_files))
        print("Calling API scans->extracting_archives")
        workbench.extract_archives(
            params.scan_code,
            params.recursively_extract_archives,
            params.jar_file_extraction
        )
    # Run scan
    workbench.run_scan(
        params.scan_code,
        params.limit,
        params.sensitivity,
        params.auto_identification_detect_declaration,
        params.auto_identification_detect_copyright,
        params.auto_identification_resolve_pending_ids,
        params.delta_only,
        params.run_dependency_analysis,
        params.reuse_identifications,
        params.identification_reuse_type,
        params.specific_code,
    )
    # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
    workbench.wait_for_scan_to_finish(
        "SCAN", params.scan_code, params.scan_number_of_tries, params.scan_wait_time
    )

    # If --run_dependency_analysis parameter is true run also dependency analysis
    if params.run_dependency_analysis:
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print("Starting dependency analysis for scan: {}".format(params.scan_code))
        workbench.start_dependency_analysis(params.scan_code)
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS", params.scan_code, params.scan_number_of_tries, params.scan_wait_time
        )

    # When scan finished retrieve licenses list by default of if parameter --get_scan_identified_components is True call
    # scans -> get_scan_identified_components
    if params.get_scan_identified_components:
        print("Identified components: ")
        identified_components = workbench.get_scan_identified_components(
            params.scan_code
        )
        print(json.dumps(identified_components))
        save_results(params=params, results=identified_components)
        sys.exit(0)

    # When scan finished retrieve project policy warnings info
    # projects ->  get_policy_warnings_info
    if params.projects_get_policy_warnings_info:
        if params.project_code is None or params.project_code == "":
            print(
                "Parameter project_code missing!\n"
                "In order for the projects->get_policy_warnings_info to be called a project code is required."
            )
            sys.exit(1)
        print(f"Project {params.project_code} policy warnings info: ")
        info_policy = workbench.projects_get_policy_warnings_info(
            params.project_code
        )
        print(json.dumps(info_policy))
        save_results(params=params, results=info_policy)
        sys.exit(0)
    else:
        print("Identified licenses: ")
        identified_licenses = workbench.get_scan_identified_licenses(params.scan_code)
        print(json.dumps(identified_licenses))
        save_results(params=params, results=identified_licenses)


main()
