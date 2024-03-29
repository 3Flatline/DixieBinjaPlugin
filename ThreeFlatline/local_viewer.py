import binaryninjaui
from binaryninja import BinaryView
import json

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import QTextBrowser, QWidget, QFormLayout, QPushButton, QBoxLayout
else:
    from PySide2.QtWidgets import QTextBrowser, QWidget, QFormLayout, QPushButton, QBoxLayout
from binaryninja.settings import Settings

from .api import DixieAPI


class DixieLocalMarkdownViewer(QWidget):
    """Custom viwer widget which links to a JMarkdownEditor."""

    dix: DixieAPI
    text_viewer: QTextBrowser
    # The currently focused BinaryView.
    bv: BinaryView

    def __init__(self, parent: QWidget, dix: DixieAPI, bv: BinaryView):
        QWidget.__init__(self, parent)
        layout = QBoxLayout(QBoxLayout.TopToBottom)
        self.setLayout(layout)
        refresh_button = QPushButton("Refresh Results")
        refresh_button.clicked.connect(self.refresh_results)
        layout.addWidget(refresh_button)
        self.bv = bv
        self.text_viewer = QTextBrowser()
        layout.addWidget(self.text_viewer)

        self.dix = dix
        self.current_results = ""


    def refresh_results(self):
        """Update the viewer when the content of the linked editor changes."""
        markdown = ""
        if not self.bv:
            print("No BinaryView selected.")
            return
        for fn in self.bv.functions:
            comment = fn.get_comment_at(0)
            if comment:
                try:
                    comment_dict = json.loads(comment)
                except json.JSONDecodeError:
                    # Not formatted for Dixie use
                    continue
                bugs_entry = ""
                for bug in comment_dict.get("bugs"):
                    bugs_entry += f"{bug}\n"
                markdown += f"""# {fn.name}
          
| Field | Content |
| --- | ----------- |
| Task Submitted | {comment_dict.get("created_at")} |
| Number of Vulns \t| {len(comment_dict.get("bugs"))} |

## Code Description

{comment_dict.get("description")}

## Vulnerabilities Detected: 

{bugs_entry}

"""
                markdown += "\n----- End Function Analysis -----\n"
        self.current_results = markdown
        self.text_viewer.setMarkdown(self.current_results)
        print("Refresh complete.")
