# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 Claudio Guarnieri.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import re
from typing import Any, Dict, List


def parse_dumpsys_receiver_resolver_table(output: str) -> Dict[str, Any]:
    results = {}

    in_receiver_resolver_table = False
    in_non_data_actions = False
    intent = None
    for line in output.splitlines():
        if line.startswith("Receiver Resolver Table:"):
            in_receiver_resolver_table = True
            continue

        if not in_receiver_resolver_table:
            continue

        if line.startswith("  Non-Data Actions:"):
            in_non_data_actions = True
            continue

        if not in_non_data_actions:
            continue

        # If we hit an empty line, the Non-Data Actions section should be
        # finished.
        if line.strip() == "":
            break

        # We detect the action name.
        if line.startswith(" " * 6) and not line.startswith(" " * 8) and ":" in line:
            intent = line.strip().replace(":", "")
            results[intent] = []
            continue

        # If we are not in an intent block yet, skip.
        if not intent:
            continue

        # If we are in a block but the line does not start with 8 spaces
        # it means the block ended a new one started, so we reset and
        # continue.
        if not line.startswith(" " * 8):
            intent = None
            continue

        # If we got this far, we are processing receivers for the
        # activities we are interested in.
        receiver = line.strip().split(" ")[1]
        package_name = receiver.split("/")[0]

        results[intent].append(
            {
                "package_name": package_name,
                "receiver": receiver,
            }
        )

    return results


def parse_dumpsys_package_for_details(output: str) -> Dict[str, Any]:
    """
    Parse one entry of a dumpsys package information
    """
    details = {
        "uid": "",
        "version_name": "",
        "version_code": "",
        "timestamp": "",
        "first_install_time": "",
        "last_update_time": "",
        "permissions": [],
        "requested_permissions": [],
    }

    in_install_permissions = False
    in_runtime_permissions = False
    in_declared_permissions = False
    in_requested_permissions = True
    for line in output.splitlines():
        if in_install_permissions:
            if line.startswith(" " * 4) and not line.startswith(" " * 6):
                in_install_permissions = False
            else:
                lineinfo = line.strip().split(":")
                permission = lineinfo[0]
                granted = None
                if "granted=" in lineinfo[1]:
                    granted = "granted=true" in lineinfo[1]

                details["permissions"].append(
                    {"name": permission, "granted": granted, "type": "install"}
                )

        if in_runtime_permissions:
            if not line.startswith(" " * 8):
                in_runtime_permissions = False
            else:
                lineinfo = line.strip().split(":")
                permission = lineinfo[0]
                granted = None
                if "granted=" in lineinfo[1]:
                    granted = "granted=true" in lineinfo[1]

                details["permissions"].append(
                    {"name": permission, "granted": granted, "type": "runtime"}
                )

        if in_declared_permissions:
            if not line.startswith(" " * 6):
                in_declared_permissions = False
            else:
                permission = line.strip().split(":")[0]
                details["permissions"].append({"name": permission, "type": "declared"})
        if in_requested_permissions:
            if not line.startswith(" " * 6):
                in_requested_permissions = False
            else:
                details["requested_permissions"].append(line.strip())

        if line.strip().startswith("userId="):
            details["uid"] = line.split("=")[1].strip()
        elif line.strip().startswith("versionName="):
            details["version_name"] = line.split("=")[1].strip()
        elif line.strip().startswith("versionCode="):
            details["version_code"] = line.split("=", 1)[1].strip()
        elif line.strip().startswith("timeStamp="):
            details["timestamp"] = line.split("=")[1].strip()
        elif line.strip().startswith("firstInstallTime="):
            details["first_install_time"] = line.split("=")[1].strip()
        elif line.strip().startswith("lastUpdateTime="):
            details["last_update_time"] = line.split("=")[1].strip()
        elif line.strip() == "install permissions:":
            in_install_permissions = True
        elif line.strip() == "runtime permissions:":
            in_runtime_permissions = True
        elif line.strip() == "declared permissions:":
            in_declared_permissions = True
        elif line.strip() == "requested permissions:":
            in_requested_permissions = True

    return details


def parse_dumpsys_packages(output: str) -> List[Dict[str, Any]]:
    """
    Parse the dumpsys package service data
    """
    pkg_rxp = re.compile(r"  Package \[(.+?)\].*")

    results = []
    package_name = None
    package = {}
    lines = []
    for line in output.splitlines():
        if line.startswith("  Package ["):
            if len(lines) > 0:
                details = parse_dumpsys_package_for_details("\n".join(lines))
                package.update(details)
                results.append(package)
                lines = []
                package = {}

            matches = pkg_rxp.findall(line)
            if not matches:
                continue

            package_name = matches[0]
            package["package_name"] = package_name
            continue

        if not package_name:
            continue

        lines.append(line)

    if len(lines) > 0:
        details = parse_dumpsys_package_for_details("\n".join(lines))
        package.update(details)
        results.append(package)

    return results
