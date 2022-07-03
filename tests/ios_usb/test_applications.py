# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2022 Claudio Guarnieri.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging

from pymobiledevice3.lockdown import LockdownClient

from mvt.common.module import run_module
from mvt.ios.modules.usb.applications import Applications


class TestUSBApplication:
    def test_run(self, mocker):
        mocker.patch("pymobiledevice3.lockdown.LockdownClient.start_service")
        mocker.patch("pymobiledevice3.usbmux.select_device")
        mocker.patch("pymobiledevice3.service_connection.ServiceConnection.create")
        mocker.patch(
            "pymobiledevice3.lockdown.LockdownClient.query_type",
            return_value="com.apple.mobile.lockdown")
        mocker.patch(
            "pymobiledevice3.lockdown.LockdownClient.validate_pairing",
            return_value=True)
        mocker.patch(
            "pymobiledevice3.services.installation_proxy.InstallationProxyService.get_apps",
            return_value=[{"CFBundleIdentifier": "com.bad.app"}]
        )

        lockdown = LockdownClient()

        m = Applications(log=logging)
        m.lockdown = lockdown
        run_module(m)
        assert len(m.results) == 2
