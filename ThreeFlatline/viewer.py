import binaryninjaui

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import QTextBrowser, QWidget, QPushButton, QBoxLayout
else:
    from PySide2.QtWidgets import QTextBrowser, QWidget, QPushButton, QBoxLayout
from binaryninja.settings import Settings

from .api import DixieAPI


class DixieMarkdownViewer(QWidget):
    """Custom viwer widget which links to a JMarkdownEditor."""

    dix: DixieAPI
    text_viewer: QTextBrowser
    
    def __init__(self, parent: QWidget, dix: DixieAPI):
        QWidget.__init__(self, parent)
        layout = QBoxLayout(QBoxLayout.TopToBottom)
        self.setLayout(layout)
        refresh_button = QPushButton("Refresh Results")
        refresh_button.clicked.connect(self.refresh_results)
        layout.addWidget(refresh_button)

        self.text_viewer = QTextBrowser()
        # self.text_viewer.resize(self.width(), self.height())
        layout.addWidget(self.text_viewer)

        self.dix = dix
        self.current_results = ""
        # Need socket for submitting an analysis based on settings.
        # self.editor.textChanged.connect(self.on_editor_text_changed)

        # self.setOpenLinks(True)
        # self.setOpenExternalLinks(True)

    def refresh_results(self):
        """Update the viewer when the content of the linked editor changes."""
        username = Settings().get_string("dixie.username")
        password = Settings().get_string("dixie.password")
        if not username or not password:
            print("Please set your Dixie username and password in the settings menu.")
            return
        self.dix.authenticate(username, password)
        markdown = ""
        raw_results = self.dix.list_tasks()
        for key, value in raw_results.items():
            markdown += self.dix.format_markdown(value)
            markdown += "\n----- End Function Analysis -----\n"
        self.current_results = markdown
        self.text_viewer.setMarkdown(self.current_results)
        self.dix.sign_out()

