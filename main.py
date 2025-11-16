from __future__ import annotations

import sys
from datetime import datetime

from PySide6.QtCore import QDate
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)

from splunk_engine import (
    SplunkClient,
    SplunkConfig,
    load_config,
    run_dispatch_multi,
)


class ReportsTab(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.config: SplunkConfig | None = None
        self.client: SplunkClient | None = None
        self.report_ids: list[str] = []
        self.report_names: list[str] = []
        self.report_email_flags: list[bool] = []

        self._build_ui()
        self._set_connected_state(False)

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Top row: server/app plus controls
        top = QHBoxLayout()
        top.addWidget(QLabel("Server:"))
        self.combo_server = QComboBox()
        top.addWidget(self.combo_server)

        top.addWidget(QLabel("App:"))
        self.combo_app = QComboBox()
        self.combo_app.setMinimumWidth(250)
        top.addWidget(self.combo_app)

        self.btn_connect = QPushButton("Connect")
        top.addWidget(self.btn_connect)

        self.btn_reload = QPushButton("Reload")
        top.addWidget(self.btn_reload)

        top.addStretch()
        layout.addLayout(top)

        # Middle row: reports list + options
        middle = QHBoxLayout()

        # Reports list
        left = QVBoxLayout()
        left.addWidget(QLabel("Reports:"))
        self.list_reports = QListWidget()
        self.list_reports.setSelectionMode(QAbstractItemView.ExtendedSelection)
        left.addWidget(self.list_reports)
        middle.addLayout(left, stretch=2)

        # Options
        right = QGridLayout()

        right.addWidget(QLabel("Frequency:"), 0, 0)
        self.combo_frequency = QComboBox()
        self.combo_frequency.addItems(["Daily", "Weekly", "Monthly"])
        right.addWidget(self.combo_frequency, 0, 1)

        right.addWidget(QLabel("Start date:"), 1, 0)
        self.date_start = QDateEdit()
        self.date_start.setCalendarPopup(True)
        self.date_start.setDate(QDate.currentDate())
        right.addWidget(self.date_start, 1, 1)

        right.addWidget(QLabel("End date:"), 2, 0)
        self.date_end = QDateEdit()
        self.date_end.setCalendarPopup(True)
        self.date_end.setDate(QDate.currentDate())
        right.addWidget(self.date_end, 2, 1)

        self.chk_no_change = QCheckBox("Use saved search time range (no override)")
        right.addWidget(self.chk_no_change, 3, 0, 1, 2)

        self.btn_send = QPushButton("Send reports")
        right.addWidget(self.btn_send, 4, 0, 1, 2)

        middle.addLayout(right, stretch=1)
        layout.addLayout(middle)

        # Log area
        layout.addWidget(QLabel("Log:"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        layout.addWidget(self.txt_log)

        # Signals
        self.combo_server.currentIndexChanged.connect(self.on_server_selection_changed)
        self.combo_app.currentIndexChanged.connect(self.on_app_changed)
        self.btn_connect.clicked.connect(self.on_connect_clicked)
        self.btn_reload.clicked.connect(self.on_reload_clicked)
        self.btn_send.clicked.connect(self.on_send_clicked)

    def load_config(self, cfg: SplunkConfig):
        self.config = cfg
        self.combo_server.clear()
        for server in cfg.servers:
            self.combo_server.addItem(server)
        if cfg.servers:
            self.combo_server.setCurrentIndex(0)
        self._set_connected_state(False)

    def append_log(self, text: str):
        self.txt_log.append(text)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

    def _set_connected_state(self, connected: bool):
        self.btn_connect.setText("Disconnect" if connected else "Connect")
        self.combo_app.setEnabled(connected)
        self.btn_reload.setEnabled(connected)
        self.btn_send.setEnabled(connected)

        if not connected:
            self.report_ids = []
            self.report_names = []
            self.report_email_flags = []
            self.combo_app.clear()
            self.list_reports.clear()

    def _disconnect(self):
        if self.client is not None:
            self.append_log("Disconnected from server.")
        self.client = None
        self._set_connected_state(False)

    def _selected_server(self) -> tuple[int, str] | None:
        if self.config is None:
            return None
        index = self.combo_server.currentIndex()
        if index < 0 or index >= len(self.config.servers):
            return None
        return index, self.config.servers[index]

    def on_server_selection_changed(self, index: int):
        if index < 0:
            return
        if self.client is not None:
            self.append_log("Server changed; disconnecting current session.")
            self._disconnect()

    def on_connect_clicked(self):
        if self.client is not None:
            self._disconnect()
            return
        self._connect_current_server()

    def _connect_current_server(self):
        selected = self._selected_server()
        if selected is None:
            QMessageBox.warning(self, "No server", "Please select a server first.")
            return

        server_url = selected[1]
        if self.config is None:
            return

        self.append_log(f"Connecting to {server_url} ...")
        try:
            client = SplunkClient(
                base_url=server_url,
                username=self.config.username,
                password=self.config.password,
            )
            apps = client.list_apps()

            self.client = client
            self.combo_app.blockSignals(True)
            self.combo_app.clear()
            for app in apps:
                self.combo_app.addItem(app)
            self.combo_app.blockSignals(False)

            self._set_connected_state(True)
            if apps:
                self.combo_app.setCurrentIndex(0)
                self.on_app_changed(0)

            self.append_log(f"Connected. {len(apps)} app(s) loaded.")
        except Exception as e:
            self.append_log(f"ERROR connecting to {server_url}: {e}")
            QMessageBox.critical(
                self,
                "Connection error",
                f"Failed to connect to {server_url}:\n{e}",
            )
            self._disconnect()

    def on_reload_clicked(self):
        if self.client is None:
            QMessageBox.warning(self, "Not connected", "Please connect to a server first.")
            return
        self.on_app_changed(self.combo_app.currentIndex())

    def on_app_changed(self, index: int):
        if self.client is None:
            return
        if index < 0:
            return

        app = self.combo_app.currentText()
        if not app:
            return

        self.append_log(f"Loading reports from app '{app}' ...")
        try:
            ids, names, email_flags = self.client.list_saved_searches(app)
            self.report_ids = ids
            self.report_names = names
            self.report_email_flags = email_flags

            self.list_reports.clear()
            for name in names:
                self.list_reports.addItem(QListWidgetItem(name))

            self.append_log(f"Loaded {len(names)} report(s).")
        except Exception as e:
            self.append_log(f"ERROR loading reports for app '{app}': {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load saved searches for app '{app}':\n{e}",
            )
            self.report_ids = []
            self.report_names = []
            self.report_email_flags = []
            self.list_reports.clear()

    def on_send_clicked(self):
        if self.client is None:
            QMessageBox.warning(self, "Not connected", "Please connect to a server first.")
            return

        selected = [idx.row() for idx in self.list_reports.selectedIndexes()]
        if not selected:
            QMessageBox.information(self, "No reports selected", "Please select at least one report.")
            return

        start_qd = self.date_start.date()
        end_qd = self.date_end.date()
        start = datetime(start_qd.year(), start_qd.month(), start_qd.day())
        end = datetime(end_qd.year(), end_qd.month(), end_qd.day())
        if end <= start:
            QMessageBox.warning(self, "Invalid date range", "End date must be after start date.")
            return

        frequency = self.combo_frequency.currentText()
        no_change = self.chk_no_change.isChecked()

        missing_email = [
            self.report_names[i]
            for i in selected
            if i < len(self.report_email_flags) and not self.report_email_flags[i]
        ]
        if missing_email:
            self.append_log(
                "WARNING: Email action disabled for the following saved searches:"
            )
            for name in missing_email:
                self.append_log(f"  - {name}")

        self.append_log("")
        self.append_log(
            f"Sending {len(selected)} report(s) - frequency={frequency}, range={start} -> {end}, no_change={no_change}"
        )

        try:
            logs = run_dispatch_multi(
                self.client,
                report_ids=self.report_ids,
                report_names=self.report_names,
                selected_indices=selected,
                frequency=frequency,
                start=start,
                end=end,
                no_change=no_change,
            )
            for line in logs:
                self.append_log(line)
        except Exception as e:
            self.append_log(f"ERROR during dispatch: {e}")
            QMessageBox.critical(
                self,
                "Dispatch error",
                f"Error while dispatching reports:\n{e}",
            )


class MainWindow(QMainWindow):
    def __init__(self, cfg: SplunkConfig, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Splunk Utility Tool v3.0")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.reports_tab = ReportsTab()
        self.tabs.addTab(self.reports_tab, "Reports")

        self.reports_tab.load_config(cfg)


def main():
    app = QApplication(sys.argv)
    try:
        cfg = load_config()
    except Exception as e:
        QMessageBox.critical(
            None,
            "Configuration error",
            f"Failed to load config.ini:\n{e}",
        )
        return

    win = MainWindow(cfg)
    win.resize(1000, 700)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

