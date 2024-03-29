from typing import Optional

from binaryninja import BinaryView
from binaryninjaui import SidebarWidget, SidebarWidgetType, SidebarWidgetLocation, \
	SidebarContextSensitivity
import binaryninjaui

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import QRectF, Qt
    from PySide6.QtWidgets import (
        QTabWidget,
        QVBoxLayout,
    )
    from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor
else:
    from PySide2.QtWidgets import (
        QTabWidget,
        QVBoxLayout,
    )

from .api import DixieAPI
from .viewer import DixieMarkdownViewer
from .settings import AnalysisSettings
from .manage import ManageTasks
from .local_viewer import DixieLocalMarkdownViewer


class DixieScannerSidebarWidget(SidebarWidget):

    # Tab container
    tab_container: QTabWidget

    # Viewer/content widget
    viewer: DixieMarkdownViewer

    # Settings widget
    dix_settings: AnalysisSettings

    # Task management widget
    task_manager: ManageTasks

    # Locally Stored Results Viewer
    local_viewer: DixieLocalMarkdownViewer

    # The currently focused BinaryView.
    bv: BinaryView

    dix: Optional[DixieAPI] = None

    def __init__(self, name, frame, bv:BinaryView):
        """
        Initialize a new DixieScannerDockWidget.

        :param parent: the QWidget to parent this NotepadDockWidget to
        :param name: the name to register the dock widget under
        :param bv: the currently focused BinaryView (may be None)
        """
        self.bv = bv
        SidebarWidget.__init__(self, "Dixie Vuln Scanner")
        # self.actionHandler.setupActionHandler(self)
        self.dix = DixieAPI()

        # Create the viewer

        self.dix_settings = AnalysisSettings(self, self.dix, self.bv)
        self.viewer = DixieMarkdownViewer(self, self.dix)
        # self.dix_settings.setWidget(AnalysisSettings(self, self.dix, self.bv))
        self.task_manager = ManageTasks(self, self.dix, self.bv)
        self.local_viewer = DixieLocalMarkdownViewer(self, self.dix, self.bv)
        # self.viewer.setWidget(DixieMarkdownViewer(self, self.dix))
        # Add both widgets to a tab container
        self.tab_container = QTabWidget()
        self.tab_container.addTab(self.dix_settings, "Analysis Settings")
        self.tab_container.addTab(self.local_viewer, "Local Function Results")
        self.tab_container.addTab(self.viewer, "View Results")
        self.tab_container.addTab(self.task_manager, "Manage Tasks")

        # Create a simple layout for the editor and set it as the root layout.
        layout = QVBoxLayout()
        layout.addWidget(self.tab_container)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.bv = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.bv = view.getData()
            self.dix_settings.bv = self.bv
            self.task_manager.bv = self.bv
            self.local_viewer.bv = self.bv

class DixieScannerSidebarWidgetType(SidebarWidgetType):
	def __init__(self):
		# Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
		# HiDPI display compatibility. They will be automatically made theme
		# aware, so you need only provide a grayscale image, where white is
		# the color of the shape.
		icon = QImage(56, 56, QImage.Format_RGB32)
		icon.fill(0)

		# Render an "H" as the example icon
		p = QPainter()
		p.begin(icon)
		p.setFont(QFont("Open Sans", 56))
		p.setPen(QColor(255, 255, 255, 255))
		p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "D")
		p.end()

		SidebarWidgetType.__init__(self, icon, "Dixie Vuln Scanner")

	def createWidget(self, frame, data):
		# This callback is called when a widget needs to be created for a given context. Different
		# widgets are created for each unique BinaryView. They are created on demand when the sidebar
		# widget is visible and the BinaryView becomes active.
		return DixieScannerSidebarWidget(SidebarWidget, "Dixie Vuln Scanner", data)

	def defaultLocation(self):
		# Default location in the sidebar where this widget will appear
		return SidebarWidgetLocation.RightContent

	def contextSensitivity(self):
		# Context sensitivity controls which contexts have separate instances of the sidebar widget.
		# Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
		# widget implementations to reduce resource usage.

		# This example widget uses a single instance and detects view changes.
		return SidebarContextSensitivity.SelfManagedSidebarContext
