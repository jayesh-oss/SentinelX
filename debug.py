import sys
import traceback
from PySide6.QtWidgets import QApplication
import ui.main_window

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        w = ui.main_window.MainWindow()
        w.show()
        print("Success!")
    except Exception as e:
        print("Crash caught:")
        traceback.print_exc()
