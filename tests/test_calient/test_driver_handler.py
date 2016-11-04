#!/usr/bin/python
# -*- coding: utf-8 -*-

import mock
import unittest

from calient import driver_handler


class TestCalientDriverHandler(unittest.TestCase):
    def setUp(self):
        super(TestCalientDriverHandler, self).setUp()
        self.src_port = "1.1.1"
        self.dst_port = "1.1.2"
        self._service_mode = "tl1"
        with mock.patch("calient.driver_handler.DriverHandlerBase"):
            with mock.patch("calient.driver_handler.ConfigurationParser"):
                self.tested_instance = driver_handler.CalientDriverHandler()
                self.tested_instance._session = mock.MagicMock()
                self.tested_instance._prompt = mock.MagicMock()

    def tearDown(self):
        super(TestCalientDriverHandler, self).tearDown()
        del self.tested_instance
        del self.src_port
        del self.dst_port

    def test_login_rest(self):
        self._service_mode = "rest"
        self.assertRaises()

    def test_get_resource_description(self):
        pass

    def test_map_bidi(self):
        pass

    def test_map_uni(self):
        pass

    def test_map_clear_to(self):
        pass

    def test_map_clear(self):
        pass
