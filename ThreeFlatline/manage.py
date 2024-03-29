from binaryninja import BinaryView
from binaryninja.settings import Settings
import binaryninjaui
from typing import Optional
import json

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem
else:
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem

from .api import DixieAPI

class ManageTasks(QWidget):
    """Custom editor widget."""
    # Dixie API
    dix: DixieAPI
    # The currently focused BinaryView.
    bv: Optional[BinaryView] = None
    

    def __init__(self, parent: QWidget, dix: DixieAPI, bv: Optional[BinaryView]):
        QWidget.__init__(self, parent)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        # The currently focused BinaryView.
        self.bv = bv
        self.dix = dix
        # # Editor should use a monospace font
        # self.setFont(binaryninjaui.getDefaultMonospaceFont())
        # Create spots for settings
        self.current_results = {}
        refresh_button = QPushButton("Refresh Task List")
        refresh_button.clicked.connect(self.refresh_results)
        self.layout.addWidget(refresh_button)
        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)
        sync_button = QPushButton("Sync Function Results in BNDB")
        self.layout.addWidget(sync_button)
        sync_button.clicked.connect(self.sync_results)
        delete_button = QPushButton("Delete Tasks")
        delete_button.clicked.connect(self.delete_tasks)
        self.layout.addWidget(delete_button)
        self.username = Settings().get_string("dixie.username") 
        self.password = Settings().get_string("dixie.password")
        if not self.username:
            print("Please set your Dixie username and password in the settings menu.")

    def sync_results(self):
        task_ids_to_sync = []
        length = self.list_widget.count()

        for i in range(0, length):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                task_name = item.text().split("\n")[0]
                print("Syncing function name:", task_name)
                task_id = item.text().split("Task ID: ")[1].split("\n")[0]
                task_ids_to_sync.append(task_id)
        for task_id in task_ids_to_sync:
            task = self.current_results.get(task_id)
            if task:
                if not self.bv:
                    print("No BinaryView selected.")
                    return
                for fn in self.bv.functions:
                    if fn.name == task.get('filepath').strip('.c'):
                        fn.set_comment_at(0, json.dumps(task))
                        break
            else:
                print(f"ERROR: Expected task results for task id {task_id}, but none were found.")
        print("Sync complete.")
            

    def refresh_results(self):
        """Update the viewer when the content of the linked editor changes."""
        self.username = Settings().get_string("dixie.username")
        self.password = Settings().get_string("dixie.password")

        if not self.username or not self.password:
            print("Please set your Dixie username and password in the settings menu.")
            return
        self.dix.authenticate(self.username, self.password)
        task_list = []
        raw_results = self.dix.list_tasks()
        for key, value in raw_results.items():
            task_list.append(value)
        self.clear_widgets()
        current_task_results = {}
        for entry in task_list:
            # Temp get around API return format
            entry_results = entry.get("results")
            if entry_results:
                entry_results = entry_results[0]
            task_id = entry.get("task_id")
            filepath = entry.get("filepath")
            created_at = entry.get("created_at")
            status = entry.get("status")
            # Parse out description safely
            try:
                description = entry_results.get("code_description")
            except AttributeError:
                description = "No description provided."
            if description:
                # Temporary for version migration on backend
                try:
                    description = description.get('description')
                except AttributeError:
                    # Leave current description var as it is correct
                    pass
            else: 
                description = "No description provided."
            try:
                bugs = entry_results.get("bugs")
            except AttributeError:
                bugs = "Not available."
            formatted_description = description.strip("Code Description:\n\n")
            box_name = f"{filepath.strip('.c')}\n\t- Task ID: {task_id}\n\t- Created Time: {created_at}\n\t- Status: {status}\n\t- Preview: {formatted_description[:200]}"
            # print(box_name)
            list_widget_item = QListWidgetItem(
                box_name,
                self.list_widget
            )
            list_widget_item.setFlags(list_widget_item.flags() | Qt.ItemIsUserCheckable)
            list_widget_item.setCheckState(Qt.Unchecked)
            self.current_results.update(
                {
                    task_id: {
                        "filepath": filepath,
                        "created_at": created_at,
                        "status": status,
                        "description": description,
                        "bugs": bugs
                    }
                }
            )
        print("Refresh complete.")

    def clear_widgets(self):
        self.list_widget.clear()

    def delete_tasks(self):
        if not self.username or not self.password:
            print("Please set your Dixie username and password in the settings menu.")
            return
        self.dix.authenticate(self.username, self.password)
        task_ids_for_deletion = []
        length = self.list_widget.count()
        for i in range(0, length):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                # print(f"Deleting {item.text()}")
                task_id = item.text().split("Task ID: ")[1].split("\n")[0]
                task_ids_for_deletion.append(task_id)
        
        self.dix.delete_tasks(task_ids_for_deletion)
        self.refresh_results()
        self.dix.sign_out()
