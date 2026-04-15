import sys
from pathlib import Path

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication

from ui.main_window import MainWindow
from ui.theme import apply_theme

SETTINGS_PATH = Path("data") / "aperio.ini"


def main():
    app = QApplication(sys.argv)

    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings = QSettings(str(SETTINGS_PATH), QSettings.Format.IniFormat)
    theme = settings.value("theme", "dark", type=str)
    apply_theme(theme)

    window = MainWindow(settings)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
