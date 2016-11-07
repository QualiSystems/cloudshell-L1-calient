#!/usr/bin/python
# -*- coding: utf-8 -*-

import mock
import unittest

from calient import driver_handler


RESPONSES = {"login": """CALIENT01TS 16-10-31 15:01:34
                         M  1 COMPLD
                         "zpollock:zpollock,2"
                         /* NOTICE This is a private computer system. Unauthorized access or use may lead to prosecution.*/
                         ;""",

             "dev_info": """CALIENT01TS 16-10-31 15:03:06
                            M  0 COMPLD
                            "CALIENT01TS:SERIALNUMBER=C00002227,SWPACKAGE=6.0-3,STATUS=OK,CHASSISTYPE=S162,PLATFORM=VERSION2"
                            ;""",

             "ports_info": """CALIENT01TS 16-11-07 11:10:16
                              M  0 COMPLD
                              "1.1.1:WX,NONE,NONE:INAS=OOS-NP,INOS=OOS,INOC=OK,INRS=NPR,OUTAS=OOS-NP,OUTOS=OOS,OUTOC=OK,OUTRS=NPR"
                              "1.1.2:WX,NONE,NONE:INAS=OOS-NP,INOS=OOS,INOC=OK,INRS=NPR,OUTAS=OOS-NP,OUTOS=OOS,OUTOC=OK,OUTRS=NPR"
                              "1.2.1:WX,NONE,NONE:INAS=OOS-NP,INOS=OOS,INOC=OK,INRS=NPR,OUTAS=OOS-NP,OUTOS=OOS,OUTOC=OK,OUTRS=NPR"
                              "6.1.1:WX,TRANSIT,TRANSIT:INAS=IS,INOS=IS,INOC=OK,INRS=NPR,OUTAS=IS,OUTOS=IS,OUTOC=OK,OUTRS=NPR"
                              ;""",

             "conn_info": """CALIENT01TS 16-11-07 11:20:14
                             M  0 COMPLD
                             "2.3.6-3.2.5:SRCPORT=2.3.6,DSTPORT=3.2.5,GRPNAME=DSTRAUB,CONNNAME=2.3.6-3.2.5,CONNTYPE=2WAY,AS=UMA,OS=RDY,OC=OK,PS=UPR,AL=CL"
                             "2.8.5>2.3.3:SRCPORT=2.8.5,DSTPORT=2.3.3,GRPNAME=DSTRAUB,CONNNAME=2.8.5>2.3.3,CONNTYPE=1WAY,AS=UMA,OS=RDY,OC=FAIL,PS=UPR,AL=CL"
                             ;""",

             "port_summary": """CALIENT01TS 16-11-04 09:26:57
                                M  0 COMPLD
                                "1.1.1:ALIAS=NONE,INPWR=NONE,OUTPWR=NONE,CONNNAME1=1.1.1>1.1.2,CONNSTATE1=ACT,CONNNAME2=NONE,CONNSTATE2=NONE"
                                ;""",

             "port_summary_not_active": """CALIENT01TS 16-11-04 09:26:57
                                           M  0 COMPLD
                                           "1.1.1:ALIAS=NONE,INPWR=NONE,OUTPWR=NONE,CONNNAME1=1.1.1>1.1.2,CONNSTATE1=NONE,CONNNAME2=NONE,CONNSTATE2=NONE"
                                           ;""",

             "port_summary_no_connection": """CALIENT01TS 16-11-04 09:26:57
                                              M  0 COMPLD
                                              "1.1.1:ALIAS=NONE,INPWR=NONE,OUTPWR=NONE,CONNNAME1=NONE,CONNSTATE1=NONE,CONNNAME2=NONE,CONNSTATE2=NONE"
                                              ;""",
             }


class TestCalientDriverHandler(unittest.TestCase):
    def setUp(self):
        super(TestCalientDriverHandler, self).setUp()
        with mock.patch("calient.driver_handler.DriverHandlerBase"):
            with mock.patch("calient.driver_handler.ConfigurationParser"):
                self.tested_instance = driver_handler.CalientDriverHandler()
                self.tested_instance._service_mode = "tl1"
                self.tested_instance._ctag = 1
                self.tested_instance._session = mock.MagicMock()
                self.tested_instance._prompt = mock.MagicMock()

    def tearDown(self):
        super(TestCalientDriverHandler, self).tearDown()
        del self.tested_instance

    def test_login_unknown_service_mode(self):
        """ Test login method with unknown service_mode """

        with self.assertRaises(Exception):
            self.tested_instance._service_mode = "unknown_service_mode"
            self.tested_instance.login("1.1.1.1", "username", "password")

    def test_login_rest_not_implemented(self):
        """ Test login method with REST service_mode """

        with self.assertRaises(NotImplementedError):
            self.tested_instance._service_mode = "rest"
            self.tested_instance.login("1.1.1.1", "username", "password")

    def test_login(self):
        """ Test login method """

        logger = mock.MagicMock()
        address = "test_host"
        username = "username"
        password = "password"
        self.tested_instance._session.send_command.return_value = RESPONSES["login"]
        self.tested_instance.login(address, username, password, logger)
        self.tested_instance._session.connect.assert_called_once_with(address, username, password, port=None)
        self.tested_instance._session.send_command.assert_called_with(data_str="ACT-USER::username:1::password;",
                                                                      re_string=self.tested_instance._prompt,
                                                                      error_map=self.tested_instance.GENERIC_ERRORS)

    def test_logout(self):
        """ Test logout method """

        logger = mock.MagicMock()
        username = "username"
        self.tested_instance.logout(username, logger)
        self.tested_instance._session.send_command.assert_called_with(data_str="CANC-USER::{}:1;".format(username),
                                                                      re_string=self.tested_instance._prompt,
                                                                      error_map=self.tested_instance.GENERIC_ERRORS)

    @mock.patch("calient.driver_handler.ResourceInfo")
    def test_get_resource_description(self, resource_info_class):
        """ Test get_resource_description method """

        resource_info = mock.MagicMock()
        logger = mock.MagicMock()
        resource_info_class.return_value = resource_info
        self.tested_instance._get_device_info = mock.MagicMock()
        self.tested_instance._get_crossconnections = mock.MagicMock()
        self.tested_instance._get_ports = mock.MagicMock()

        with mock.patch("re.search"):
            result = self.tested_instance.get_resource_description('test_address', logger)

        self.tested_instance._get_device_info.assert_called_once()
        self.tested_instance._get_crossconnections.assert_called_once()
        self.tested_instance._get_ports.assert_called_once()
        resource_info.convert_to_xml.assert_called_once()
        self.assertEquals(result, resource_info.convert_to_xml())

    def test__get_device_info(self):
        """ Test _get_device_info method """

        self.tested_instance._session.send_command.return_value = RESPONSES["dev_info"]

        result = self.tested_instance._get_device_info()
        self.tested_instance._session.send_command.assert_called_with(data_str="RTRV-NE;",
                                                                      re_string=self.tested_instance._prompt,
                                                                      error_map=self.tested_instance.GENERIC_ERRORS)

        self.assertEqual(result, {"serial": "C00002227", "version": "6.0-3", "model": "S162"})

    def test__get_ports(self):
        """ Test _get_ports method """

        self.tested_instance._session.send_command.return_value = RESPONSES["ports_info"]

        result = self.tested_instance._get_ports()
        self.tested_instance._session.send_command.assert_called_with(data_str="RTRV-PORT::0;",
                                                                      re_string=self.tested_instance._prompt,
                                                                      error_map=self.tested_instance.GENERIC_ERRORS)
        self.assertEqual(result, [{"port_name": "1-1-1"},
                                  {"port_name": "1-1-2"},
                                  {"port_name": "1-2-1"},
                                  {"port_name": "6-1-1"}])

    def test__get_crossconnections(self):
        """ Test _get_crossconnections method """

        self.tested_instance._session.send_command.return_value = RESPONSES["conn_info"]

        result = self.tested_instance._get_crossconnections()
        self.tested_instance._session.send_command.assert_called_with(data_str="RTRV-CRS:::::ALL;",
                                                                      re_string=self.tested_instance._prompt,
                                                                      error_map=self.tested_instance.GENERIC_ERRORS)
        self.assertEqual(result, {"3-2-5": "2-3-6",
                                  "2-3-6": "3-2-5",
                                  "2-3-3": "2-8-5"})

    def test_map_bidi(self):
        """ Test creation of BI-direction connection """

        logger = mock.MagicMock()
        self.tested_instance._create_crossconnection = mock.MagicMock()

        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        self.tested_instance.map_bidi(src_port, dst_port, logger)

        self.tested_instance._create_crossconnection.assert_called_once_with(src_port=src_port,
                                                                             dst_port=dst_port,
                                                                             conn_type="2WAY")

    def test_map_bidi_loopback(self):
        """ Test creation of BI-direction connection with equal src and dst ports """

        logger = mock.MagicMock()
        self.tested_instance._create_crossconnection = mock.MagicMock()

        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-1"]
        self.tested_instance.map_bidi(src_port, dst_port, logger)

        self.tested_instance._create_crossconnection.assert_called_once_with(src_port=src_port,
                                                                             dst_port=dst_port,
                                                                             conn_type="1WAY")

    def test_map_uni(self):
        """ Test creation of UNI-direction connection """

        logger = mock.MagicMock()
        self.tested_instance._create_crossconnection = mock.MagicMock()

        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        self.tested_instance.map_uni(src_port, dst_port, logger)

        self.tested_instance._create_crossconnection.assert_called_once_with(src_port=src_port,
                                                                             dst_port=dst_port,
                                                                             conn_type="1WAY")

    def test__create_crossconnection(self):
        """ Test _create_crossconnection method """

        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        conn_type = "1WAY"

        self.tested_instance._create_crossconnection(src_port, dst_port, conn_type)

        self.tested_instance._session.send_command.assert_has_calls([
            mock.call(data_str=("ENT-CRS::{src_port},{dst_port}:1::{group_name},{conn_type};"
                      .format(src_port=src_port[-1].replace("-", "."),
                              dst_port=dst_port[-1].replace("-", "."),
                              group_name=self.tested_instance.GROUP_NAME,
                              conn_type=conn_type)),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS),
            mock.call(data_str=("ACT-CRS::{src_port},{dst_port}:1::{src_port}{cur_delimiter}{dst_port},{group_name};"
                      .format(src_port=src_port[-1].replace("-", "."),
                              dst_port=dst_port[-1].replace("-", "."),
                              cur_delimiter=self.tested_instance.CONN_MAP[conn_type],
                              group_name=self.tested_instance.GROUP_NAME)),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS)]
        )

    def test_map_clear_to_no_connection(self):
        """ Test deleting UNI-direction connection when connection doesn't exist """

        logger = mock.MagicMock()
        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        self.tested_instance._session.send_command.return_value = RESPONSES["port_summary_no_connection"]

        self.tested_instance.map_clear_to(src_port, dst_port, logger)

        self.tested_instance._session.send_command.assert_called_once_with(
            data_str="RTRV-PORT-SUM::{src_port};".format(src_port=src_port[-1].replace("-", ".")),
            re_string=self.tested_instance._prompt,
            error_map=self.tested_instance.GENERIC_ERRORS)

    def test_map_clear_to_not_active_connection(self):
        """ Test deleting UNI-direction connection when connection isn't active """

        logger = mock.MagicMock()
        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        self.tested_instance._session.send_command.return_value = RESPONSES["port_summary_not_active"]

        self.tested_instance.map_clear_to(src_port, dst_port, logger)

        self.tested_instance._session.send_command.assert_has_calls([
            mock.call(data_str="RTRV-PORT-SUM::{src_port};".format(src_port=src_port[-1].replace("-", ".")),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS),
            mock.call(data_str="DLT-CRS::{src_port},{dst_port}:1::,{group_name},1.1.1>1.1.2;"
                               .format(src_port=src_port[-1].replace("-", "."),
                                       dst_port=dst_port[-1].replace("-", "."),
                                       group_name=self.tested_instance.GROUP_NAME),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS)]
        )

    def test_map_clear_to(self):
        """ Test deleting UNI-direction connection """

        logger = mock.MagicMock()
        src_port = ["address", "1-1-1"]
        dst_port = ["address", "1-1-2"]
        self.tested_instance._session.send_command.return_value = RESPONSES["port_summary"]

        self.tested_instance.map_clear_to(src_port, dst_port, logger)

        self.tested_instance._session.send_command.assert_has_calls([
            mock.call(data_str="RTRV-PORT-SUM::{src_port};".format(src_port=src_port[-1].replace("-", ".")),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS),
            mock.call(data_str="CANC-CRS::{src_port},{dst_port}:1::,{group_name},1.1.1>1.1.2;"
                      .format(src_port=src_port[-1].replace("-", "."),
                              dst_port=dst_port[-1].replace("-", "."),
                              group_name=self.tested_instance.GROUP_NAME),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS),
            mock.call(data_str="DLT-CRS::{src_port},{dst_port}:1::,{group_name},1.1.1>1.1.2;"
                               .format(src_port=src_port[-1].replace("-", "."),
                                       dst_port=dst_port[-1].replace("-", "."),
                                       group_name=self.tested_instance.GROUP_NAME),
                      re_string=self.tested_instance._prompt,
                      error_map=self.tested_instance.GENERIC_ERRORS)]
        )

    def test_map_clear(self):
        """ Test deleting BI-direction connection """

        logger = mock.MagicMock()
        src_port_input = mock.MagicMock()
        dst_port_input = mock.MagicMock()
        self.tested_instance.map_clear_to = mock.MagicMock()
        self.tested_instance.map_clear(src_port=src_port_input, dst_port=dst_port_input, command_logger=logger)
        self.tested_instance.map_clear_to.assert_called_once_with(src_port_input, dst_port_input, logger)
