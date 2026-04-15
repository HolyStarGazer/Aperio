from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication


BASE_QSS = """
/* === Sidebar === */
QPushButton#sidebarTab,
QPushButton#sidebarHamburger,
QPushButton#sidebarTheme {
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-radius: 5px;
    background-color: transparent;
}
QPushButton#sidebarTab:hover,
QPushButton#sidebarHamburger:hover,
QPushButton#sidebarTheme:hover {
    background-color: rgba(128, 128, 128, 45);
}
QPushButton#sidebarTab:pressed,
QPushButton#sidebarHamburger:pressed,
QPushButton#sidebarTheme:pressed {
    background-color: rgba(128, 128, 128, 90);
}

/* === Card frames === */
QFrame#deviceCard,
QFrame#recentCaptureCard,
QFrame#statCard {
    background-color: palette(alternate-base);
    border: 1px solid palette(mid);
    border-radius: 6px;
}

/* === Buttons (flat, rounded, clear hover) === */
QPushButton {
    background-color: palette(button);
    border: 1px solid palette(mid);
    border-radius: 5px;
    padding: 6px 14px;
    color: palette(button-text);
    min-height: 20px;
}
QPushButton:hover {
    background-color: palette(midlight);
}
QPushButton:pressed {
    background-color: palette(dark);
}
QPushButton:disabled {
    color: palette(mid);
    background-color: palette(alternate-base);
}

/* === Line edits / spin boxes / combo boxes === */
QLineEdit,
QSpinBox,
QDoubleSpinBox,
QComboBox {
    background-color: palette(base);
    border: 1px solid palette(mid);
    border-radius: 4px;
    padding: 5px 9px;
    color: palette(text);
    selection-background-color: palette(highlight);
    selection-color: palette(highlighted-text);
    min-height: 20px;
}
QLineEdit:focus,
QSpinBox:focus,
QDoubleSpinBox:focus,
QComboBox:focus {
    border: 1px solid palette(highlight);
}
QLineEdit:disabled,
QSpinBox:disabled,
QComboBox:disabled {
    color: palette(mid);
    background-color: palette(alternate-base);
}
QComboBox::drop-down {
    border: none;
    width: 22px;
}

/* === Check boxes === */
QCheckBox {
    spacing: 8px;
    color: palette(text);
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid palette(mid);
    border-radius: 3px;
    background-color: palette(base);
}
QCheckBox::indicator:hover {
    border-color: palette(highlight);
}
QCheckBox::indicator:checked {
    background-color: palette(highlight);
    border-color: palette(highlight);
}

/* === Tables and tree views === */
QTableView,
QTreeView,
QTreeWidget,
QListWidget {
    background-color: palette(base);
    alternate-background-color: palette(alternate-base);
    gridline-color: transparent;
    border: 1px solid palette(mid);
    border-radius: 5px;
    selection-background-color: palette(highlight);
    selection-color: palette(highlighted-text);
    outline: 0;
}
QTableView::item,
QTreeView::item,
QTreeWidget::item,
QListWidget::item {
    padding: 3px 4px;
}

/* === Table column headers (flat, bottom-border only) === */
QHeaderView::section {
    background-color: palette(alternate-base);
    color: palette(text);
    padding: 8px 12px;
    border: none;
    border-bottom: 2px solid palette(mid);
    font-weight: 600;
}
QHeaderView::section:horizontal:pressed {
    background-color: palette(midlight);
}

/* === Progress bars === */
QProgressBar {
    background-color: palette(alternate-base);
    border: 1px solid palette(mid);
    border-radius: 4px;
    text-align: center;
    color: palette(text);
    min-height: 18px;
}
QProgressBar::chunk {
    background-color: palette(highlight);
    border-radius: 3px;
    margin: 1px;
}

/* === Scroll bars === */
QScrollBar:vertical {
    background: palette(alternate-base);
    width: 12px;
    margin: 0;
    border: none;
}
QScrollBar::handle:vertical {
    background: palette(mid);
    border-radius: 6px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: palette(dark);
}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: palette(alternate-base);
    height: 12px;
    margin: 0;
    border: none;
}
QScrollBar::handle:horizontal {
    background: palette(mid);
    border-radius: 6px;
    min-width: 28px;
}
QScrollBar::handle:horizontal:hover {
    background: palette(dark);
}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0;
}

/* === Splitter === */
QSplitter::handle {
    background-color: palette(mid);
}
QSplitter::handle:horizontal {
    width: 2px;
}
QSplitter::handle:vertical {
    height: 2px;
}
"""


DARK_QSS = ""


def light_palette() -> QPalette:
    palette = QPalette()

    window = QColor(242, 242, 242)
    window_text = QColor(25, 25, 25)
    base = QColor(255, 255, 255)
    alternate = QColor(246, 246, 246)
    button = QColor(238, 238, 238)
    text = QColor(25, 25, 25)
    highlight = QColor(0, 120, 215)
    highlighted_text = QColor(255, 255, 255)
    tooltip_base = QColor(255, 255, 225)
    tooltip_text = QColor(25, 25, 25)
    disabled = QColor(160, 160, 160)
    bright_text = QColor(200, 0, 0)
    link = QColor(0, 80, 200)
    mid = QColor(200, 200, 200)
    midlight = QColor(225, 225, 225)
    light = QColor(250, 250, 250)
    dark = QColor(180, 180, 180)
    shadow = QColor(120, 120, 120)

    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, window_text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, alternate)
    palette.setColor(QPalette.ColorRole.ToolTipBase, tooltip_base)
    palette.setColor(QPalette.ColorRole.ToolTipText, tooltip_text)
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(135, 135, 135))
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, button)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, bright_text)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, highlighted_text)
    palette.setColor(QPalette.ColorRole.Link, link)
    palette.setColor(QPalette.ColorRole.LinkVisited, link)
    palette.setColor(QPalette.ColorRole.Shadow, shadow)
    palette.setColor(QPalette.ColorRole.Midlight, midlight)
    palette.setColor(QPalette.ColorRole.Mid, mid)
    palette.setColor(QPalette.ColorRole.Light, light)
    palette.setColor(QPalette.ColorRole.Dark, dark)

    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.WindowText,
        disabled,
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.Text,
        disabled,
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.ButtonText,
        QColor(180, 180, 180),
    )

    return palette


def dark_palette() -> QPalette:
    palette = QPalette()

    window = QColor(30, 30, 30)
    window_text = QColor(220, 220, 220)
    base = QColor(22, 22, 22)
    alternate = QColor(38, 38, 38)
    button = QColor(45, 45, 45)
    text = QColor(220, 220, 220)
    highlight = QColor(61, 120, 180)
    highlighted_text = QColor(255, 255, 255)
    tooltip_base = QColor(50, 50, 50)
    disabled = QColor(120, 120, 120)
    disabled_button_text = QColor(110, 110, 110)
    bright_text = QColor(255, 80, 80)
    link = QColor(100, 160, 230)
    shadow = QColor(0, 0, 0)
    midlight = QColor(55, 55, 55)
    mid = QColor(70, 70, 70)
    light = QColor(80, 80, 80)
    dark = QColor(15, 15, 15)

    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, window_text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, alternate)
    palette.setColor(QPalette.ColorRole.ToolTipBase, tooltip_base)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(150, 150, 150))
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, button)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, bright_text)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, highlighted_text)
    palette.setColor(QPalette.ColorRole.Link, link)
    palette.setColor(QPalette.ColorRole.LinkVisited, link)
    palette.setColor(QPalette.ColorRole.Shadow, shadow)
    palette.setColor(QPalette.ColorRole.Midlight, midlight)
    palette.setColor(QPalette.ColorRole.Mid, mid)
    palette.setColor(QPalette.ColorRole.Light, light)
    palette.setColor(QPalette.ColorRole.Dark, dark)

    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.WindowText,
        disabled,
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.Text,
        disabled,
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.ButtonText,
        disabled_button_text,
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.Base,
        QColor(26, 26, 26),
    )

    return palette


def apply_theme(theme: str) -> None:
    app = QApplication.instance()
    if app is None:
        return

    app.setStyle("Fusion")

    if theme == "dark":
        app.setPalette(dark_palette())
        app.setStyleSheet(BASE_QSS + DARK_QSS)
    else:
        app.setPalette(light_palette())
        app.setStyleSheet(BASE_QSS)
