from PySide6.QtWidgets import QWidget, QCheckBox
from PySide6.QtCore import Qt, QRect, QPropertyAnimation, QEasingCurve, QPoint, Property, QSize
from PySide6.QtGui import QPainter, QColor, QBrush, QFontMetrics

class ToggleSwitch(QCheckBox):
    def __init__(self, text="", parent=None, active_color="#00C853"):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.active_color = QColor(active_color)
        self.bg_color = QColor("#333333")
        self.circle_color = QColor("#FFFFFF")
        
        # Dimensions
        self._thumb_radius = 12
        self._track_height = 24
        self._track_width = 48
        
        # Animations
        self._position = 0
        self.animation = QPropertyAnimation(self, b"thumb_position", self)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.setDuration(150)
        
        self.stateChanged.connect(self._setup_animation)

    @Property(float)
    def thumb_position(self):
        return self._position

    @thumb_position.setter
    def thumb_position(self, pos):
        self._position = pos
        self.update()

    def _setup_animation(self, value):
        self.animation.stop()
        if value:
            self.animation.setEndValue(1)
        else:
            self.animation.setEndValue(0)
        self.animation.start()

    def hitButton(self, pos: QPoint):
        return self.contentsRect().contains(pos)
        
    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Track Rectangle
        rect = QRect(0, 0, self._track_width, self._track_height)
        
        # Interpolate background color
        r = int(self.bg_color.red() + self._position * (self.active_color.red() - self.bg_color.red()))
        g = int(self.bg_color.green() + self._position * (self.active_color.green() - self.bg_color.green()))
        b = int(self.bg_color.blue() + self._position * (self.active_color.blue() - self.bg_color.blue()))
        current_bg = QColor(r, g, b)
        
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(current_bg))
        p.drawRoundedRect(rect, self._track_height / 2, self._track_height / 2)
        
        # Thumb Circle
        thumb_x = int(self._position * (self._track_width - self._track_height))
        thumb_rect = QRect(thumb_x + 2, 2, self._track_height - 4, self._track_height - 4)
        p.setBrush(QBrush(self.circle_color))
        p.drawEllipse(thumb_rect)

        # Draw the Text next to the toggle
        text = self.text()
        if text:
            # We want to draw text slightly to the right of the track
            p.setPen(QColor("#C9D1D9"))
            if not self.isEnabled():
                p.setPen(QColor("#8B949E"))
            p.drawText(
                QRect(self._track_width + 10, 0, self.width() - self._track_width - 10, self._track_height),
                Qt.AlignLeft | Qt.AlignVCenter,
                text
            )
            
    def sizeHint(self):
        fm = QFontMetrics(self.font())
        return QSize(self._track_width + 15 + fm.horizontalAdvance(self.text()), self._track_height)
