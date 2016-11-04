#!/usr/bin/python
# -*- coding: utf-8 -*-

from common import request_handler
from common.xml_wrapper import XMLWrapper


class CalientRequestHandler(request_handler.RequestHandler):
    """Extend base request_handler.RequestHandler class with additional driver actions"""

    def logout(self, command_node, xs_prefix='', command_logger=None):
        """
        <Commands xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Command CommandName="Logout" CommandId="567f4dc1-e2e5-4980-b726-a5d906c8679b">
                <Parameters xsi:type="LogoutCommandParameters">
                    <User>root</User>
                </Parameters>
            </Command>
        </Commands>
        """
        command_logger.info(XMLWrapper.get_string_from_xml(command_node))
        parameters_node = XMLWrapper.get_child_node(command_node, 'Parameters', xs_prefix)
        username = XMLWrapper.get_child_node(parameters_node, 'User', xs_prefix)
        return self._driver_handler.logout(username, command_logger)
