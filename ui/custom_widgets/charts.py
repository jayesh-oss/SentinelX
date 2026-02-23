from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtGui import QPainter, QColor, QBrush, QPen, QFont
from PySide6.QtCore import Qt, QRectF

class DonutChartWidget(QWidget):
    def __init__(self, clean_count=0, malware_count=0):
        super().__init__()
        self.setMinimumSize(200, 200)
        self.clean_count = clean_count
        self.malware_count = malware_count

    def update_data(self, clean_count, malware_count):
        self.clean_count = clean_count
        self.malware_count = malware_count
        self.update() # Repaint

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        total = self.clean_count + self.malware_count
        if total == 0:
            total = 1 # Prevent division by zero, draw a gray empty circle
            clean_angle = 0
            malware_angle = 360 * 16
        else:
            clean_angle = int((self.clean_count / total) * 360 * 16)
            malware_angle = 360 * 16 - clean_angle

        rect = QRectF(20, 20, self.width() - 40, self.height() - 40)
        
        # Draw Malware (Red)
        painter.setPen(Qt.NoPen)
        if total == 1 and self.clean_count == 0 and self.malware_count == 0:
            painter.setBrush(QBrush(QColor("#30363D"))) # Gray placeholder
            painter.drawPie(rect, 0, malware_angle)
        else:
            painter.setBrush(QBrush(QColor("#F85149"))) # Red
            painter.drawPie(rect, 0, malware_angle)
            
            # Draw Clean (Green)
            painter.setBrush(QBrush(QColor("#3FB950"))) # Green
            painter.drawPie(rect, malware_angle, clean_angle)

        # Draw Inner Circle (Donut hole) to match background
        # By making inner_rect larger, there is more room for the text
        inner_rect = QRectF(40, 40, self.width() - 80, self.height() - 80)
        
        # We assume background is slightly dark like #161B22
        painter.setBrush(QBrush(QColor("#161B22")))
        painter.drawEllipse(inner_rect)
        
        # Draw Total Text
        if total == 1 and self.clean_count == 0 and self.malware_count == 0:
            display_total = 0
        else:
            display_total = total
            
        # Draw Total Text (Shifted UP)
        painter.setPen(QColor("#E6EDF3"))
        font = QFont("Segoe UI", 20, QFont.Bold)
        painter.setFont(font)
        number_rect = QRectF(inner_rect.x(), inner_rect.y() - 12, inner_rect.width(), inner_rect.height())
        painter.drawText(number_rect, Qt.AlignCenter, str(display_total))
        
        # Subtext (Shifted DOWN)
        font2 = QFont("Segoe UI", 8)
        painter.setFont(font2)
        sub_rect = QRectF(inner_rect.x(), inner_rect.y() + 15, inner_rect.width(), inner_rect.height())
        painter.setPen(QColor("#8B949E"))
        painter.drawText(sub_rect, Qt.AlignCenter, "Total Scans")
