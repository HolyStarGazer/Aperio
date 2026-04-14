import sys

from PyQt6.QtWidgets import QApplication, QLabel

app = QApplication(sys.argv)

label = QLabel("Hello, window")
label.show()

sys.exit(app.exec())
