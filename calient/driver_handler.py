#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
from collections import OrderedDict

from common.driver_handler_base import DriverHandlerBase
from common.configuration_parser import ConfigurationParser
from common.resource_info import ResourceInfo


class CalientDriverHandler(DriverHandlerBase):
    GROUP_NAME = "Quali"
    CONN_MAP = {"1WAY": ">",
                "2WAY": "-"}

    GENERIC_ERRORS = OrderedDict([
        ("[Ii]nvalid", "Command is invalid"),
        ("[Ll]ogin [Nn]ot [Aa]ctive", "User is not logged in"),
        ("[Ff]ailed", "Failed to perform command"),
    ])

    def __init__(self):
        DriverHandlerBase.__init__(self)
        self._ctag = 1
        self._switch_name = ""

        self._service_mode = ConfigurationParser.get("driver_variable", "service_mode")

    def _incr_ctag(self):
        self._ctag += 1
        return self._ctag

    def login(self, address, username, password, command_logger=None):
        """ Perform login operation on the device

        :param address: (str) address attribute from the CloudShell portal
        :param username: (str) username to login on the device
        :param password: (str) password for username
        :param command_logger: logging.Logger instance
        :return: None
        """

        self._session.connect(address, username, password, port=None)

        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":
            command = "ACT-USER::{username}:{ctag}::{password};".format(username=username,
                                                                        ctag=self._ctag,
                                                                        password=password)
            command_result = self._session.send_command(data_str=command,
                                                        re_string=self._prompt,
                                                        error_map=self.GENERIC_ERRORS)
            command_logger.info(command_result)

            if "COMPLD" in command_result or "Already logged in" in command_result:
                command_logger.info("Login status: OK")
            else:
                command_logger.info("Didn't find success login message. Retrying ...")
                command_result = self._session.send_command(data_str=command,
                                                            re_string=self._prompt,
                                                            error_map=self.GENERIC_ERRORS)
                command_logger.info(command_result)

            match_result = re.search(r"\s+(?P<host>\S+)\s.+M", command_result, re.DOTALL)
            if match_result:
                self._switch_name = match_result.groupdict()["host"]
        else:
            raise Exception(self.__class__.__name__, "From service mode type (current mode: '" +
                            self._service_mode + "'!")

    def logout(self, username, command_logger=None):
        """ Perform logout operation on the device

        :param username: (str) username to logout from the device
        :param command_logger: logging.Logger instance
        :return: None
        """

        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":
            command = "CANC-USER::{username}:{ctag};".format(username=username, ctag=self._ctag)
            command_result = self._session.send_command(data_str=command,
                                                        re_string=self._prompt,
                                                        error_map=self.GENERIC_ERRORS)
            command_logger.info(command_result)
            if "COMPLD" not in command_result:
                command_logger.info("Didn't find success logoff message. Retrying ...")
                command_result = self._session.send_command(data_str=command,
                                                            re_string=self._prompt,
                                                            error_map=self.GENERIC_ERRORS)
                command_logger.info(command_result)
            else:
                command_logger.info("Logoff status: OK")

    def get_resource_description(self, address, command_logger=None):
        """ Auto-load function to retrieve all information from the device

        :param address: (str) address attribute from the CloudShell portal
        :param command_logger: logging.Logger instance
        :return: xml.etree.ElementTree.Element instance with all switch sub-resources (blades, ports)
        """

        resource_info = ResourceInfo()
        resource_info.set_depth(0)
        resource_info.set_address(address)

        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":

            dev_info = self._get_device_info()
            resource_info.add_attribute("Vendor", "Calient")
            resource_info.add_attribute("Version", dev_info.get("version", ""))
            model_name = dev_info.get("model", "")
            resource_info.set_model_name(model_name)
            resource_info.set_serial_number(dev_info.get("serial", ""))

            connection_info = self._get_crossconnections()

            for port_info in self._get_ports():
                port_resource_info = ResourceInfo()
                port_resource_info.set_depth(1)

                port_name = port_info.get("port_name")
                port_resource_info.set_index(port_name)
                if port_name in connection_info:
                    port_resource_info.set_mapping("{address}/{dst_port}".format(address=address,
                                                                                 dst_port=connection_info[port_name]))

                port_resource_info.add_attribute("Protocol Type", 0)
                port_resource_info.set_model_name(model_name)

                resource_info.add_child(port_name, port_resource_info)

        return resource_info.convert_to_xml()

    def _get_device_info(self):
        """ Get device information such as Vendor, Type, Version, Model

        :return: result: (dict) device information
        """

        command = "RTRV-NE;"
        command_result = self._session.send_command(data_str=command,
                                                    re_string=self._prompt,
                                                    error_map=self.GENERIC_ERRORS)

        regex = r'SERIALNUMBER=(?P<serial>\S+),SWPACKAGE=(?P<version>\S+),STATUS=.+,CHASSISTYPE=(?P<model>[\w\.-]+).*"'
        match = re.search(regex, command_result, re.IGNORECASE | re.DOTALL)
        if match:
            return {"serial": match.group("serial"), "version": match.group("version"), "model": match.group("model")}
        else:
            return dict()

    def _get_ports(self):
        """ Get device ports list

        :return: result: (list) device ports information list
        """

        result = []
        command = "RTRV-PORT::0;"
        command_result = self._session.send_command(data_str=command,
                                                    re_string=self._prompt,
                                                    error_map=self.GENERIC_ERRORS)

        regex = r'"(?P<port_name>[\w\.-]+):(?P<port_type>[\w\.-]+),'
        for port_info in re.finditer(regex, command_result, re.IGNORECASE | re.DOTALL):
            result.append({"port_name": port_info.group("port_name").replace(".", "-")})

        return result

    def _get_crossconnections(self):
        """ Get device cross-connections list

        :return: result: (dict) device cross-connection information
        """

        result = {}
        regex = (r"SRCPORT=(?P<src_port>\S+),"
                 r"DSTPORT=(?P<dst_port>\S+),"
                 r"GRPNAME=(?P<group_name>\S+),"
                 r"CONNNAME=(?P<conn_name>\S+),"
                 r"CONNTYPE=(?P<conn_type>\w+)")

        command = "RTRV-CRS:::::ALL;"
        command_result = self._session.send_command(data_str=command,
                                                    re_string=self._prompt,
                                                    error_map=self.GENERIC_ERRORS)

        for conn_info in re.finditer(regex, command_result, re.IGNORECASE | re.DOTALL):
            result.update({conn_info.group("dst_port").replace(".", "-"):
                           conn_info.group("src_port").replace(".", "-")})
            if conn_info.group("conn_type").lower() == "2way":
                result.update({conn_info.group("src_port").replace(".", "-"):
                               conn_info.group("dst_port").replace(".", "-")})

        return result

    def map_bidi(self, src_port, dst_port, command_logger):
        """ Create a bidirectional connection between source and destination ports

        :param src_port: (list) source port in format ["<address>", "<port>"]
        :param dst_port: (list) destination port in format ["<address>", "<port>"]
        :param command_logger: logging.Logger instance
        """

        if src_port == dst_port:
            conn_type = "1WAY"
        else:
            conn_type = "2WAY"

        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":
            self._create_crossconnection(src_port=src_port, dst_port=dst_port, conn_type=conn_type)

    def map_uni(self, src_port, dst_port, command_logger):
        """ Create a unidirectional connection between source and destination ports

        :param src_port: (list) source port in format ["<address>", "<port>"]
        :param dst_port: (list) destination port in format ["<address>", "<port>"]
        :param command_logger: logging.Logger instance
        """

        conn_type = "1WAY"
        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":
            self._create_crossconnection(src_port=src_port, dst_port=dst_port, conn_type=conn_type)

    def _create_crossconnection(self, src_port, dst_port, conn_type):
        """ Create a connection between source and destination ports

        :param src_port: (list) source port in format ["<address>", "<port>"]
        :param dst_port: (list) destination port in format ["<address>", "<port>"]
        :param conn_type: (str) connection type. Might be UNI or BI
        :param command_logger: logging.Logger instance
        """

        src_port = src_port[-1].replace("-", ".")
        dst_port = dst_port[-1].replace("-", ".")
        curcuit_delimiter = self.CONN_MAP[conn_type]

        command = "ENT-CRS::{src_port},{dst_port}:{ctag}::{group_name},{conn_type};".format(src_port=src_port,
                                                                                            dst_port=dst_port,
                                                                                            ctag=self._ctag,
                                                                                            group_name=self.GROUP_NAME,
                                                                                            conn_type=conn_type)

        self._session.send_command(data_str=command, re_string=self._prompt, error_map=self.GENERIC_ERRORS)

        command = "ACT-CRS::{src_port},{dst_port}:{ctag}::{src_port}{cur_delimiter}{dst_port},{group_name};" \
            .format(src_port=src_port,
                    dst_port=dst_port,
                    ctag=self._ctag,
                    group_name=self.GROUP_NAME,
                    cur_delimiter=curcuit_delimiter)

        self._session.send_command(data_str=command, re_string=self._prompt, error_map=self.GENERIC_ERRORS)

    def map_clear_to(self, src_port, dst_port, command_logger):
        """ Remove simplex/multi-cast/duplex connection ending on the destination port

        :param src_port: (list) source port in format ["<address>", "<port>"]
        :param dst_port: (list) destination port in format ["<address>", "<port>"]
        :param command_logger: logging.Logger instance
        """

        if self._service_mode.lower() == "rest":
            raise NotImplementedError
        elif self._service_mode.lower() == "tl1":
            src_port = src_port[-1].replace("-", ".")
            dst_port = dst_port[-1].replace("-", ".")

            port_info = self._session.send_command(data_str="RTRV-PORT-SUM::{src_port};".format(src_port=src_port),
                                                   re_string=self._prompt,
                                                   error_map=self.GENERIC_ERRORS)

            regex = r"CONNNAME1=(?P<conn_name>\S+),CONNSTATE1=(?P<conn_state>\w+)"
            match = re.search(regex, port_info, re.IGNORECASE | re.DOTALL)

            if match:
                conn_name = match.group("conn_name")
                conn_state = match.group("conn_state")

                if conn_name.lower() != "none":
                    if conn_state == "ACT":
                        command = ("CANC-CRS::{src_port},{dst_port}:{ctag}::,{group_name},{conn_name};"
                                   .format(src_port=src_port,
                                           dst_port=dst_port,
                                           ctag=self._ctag,
                                           group_name=self.GROUP_NAME,
                                           conn_name=conn_name))
                        self._session.send_command(data_str=command,
                                                   re_string=self._prompt,
                                                   error_map=self.GENERIC_ERRORS)

                    command = ("DLT-CRS::{src_port},{dst_port}:{ctag}::,{group_name},{conn_name};"
                               .format(src_port=src_port,
                                       dst_port=dst_port,
                                       ctag=self._ctag,
                                       group_name=self.GROUP_NAME,
                                       conn_name=conn_name))

                    self._session.send_command(data_str=command, re_string=self._prompt, error_map=self.GENERIC_ERRORS)

    def map_clear(self, src_port, dst_port, command_logger):
        """ Remove simplex/multi-cast/duplex connection ending on the destination port

        :param src_port: (list) source port in format ["<address>", "<port>"]
        :param dst_port: (list) destination port in format ["<address>", "<port>"]
        :param command_logger: logging.Logger instance
        :return: None
        """

        self.map_clear_to(src_port, dst_port, command_logger)

    def set_speed_manual(self, command_logger):
        """ Set speed manual - skipped command

        :param command_logger: logging.Logger instance
        :return: None
        """
        pass
