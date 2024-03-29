#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pdb import run
import binaryninjaui

from binaryninja.settings import Settings
from binaryninja.interaction import *
from .ThreeFlatline.widget import DixieScannerSidebarWidgetType

Settings().register_group("dixie", "Dixie Vuln Scanner")
Settings().register_setting("dixie.password", """
    {
        "title" : "Password",
        "type" : "string",
        "default" : "",
        "description" : "The password used to login to the 3Flatline Dixie API",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("dixie.username", """
    {
        "title" : "Username",
        "type" : "string",
        "default" : "",
        "description" : "The username used to login to the 3Flatline Dixie API",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)

binaryninjaui.Sidebar.addSidebarWidgetType(DixieScannerSidebarWidgetType())
