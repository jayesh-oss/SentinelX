from PySide6.QtWidgets import QWidget
from PySide6.QtGui import QPainter, QColor, QPen, QFont
from PySide6.QtCore import Qt, QRectF, QTimer


class DonutChartWidget(QWidget):
    def __init__(self, clean_count=0, malware_count=0):
        super().__init__()
        self.setMinimumSize(160, 160)

        self._target_clean = clean_count
        self._target_malware = malware_count
        self._progress = 1.0  # start complete so initial state draws instantly

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._step)

    def update_data(self, clean_count, malware_count):
        self._target_clean = clean_count
        self._target_malware = malware_count
        self._progress = 0.0
        self._timer.start(16)  # ~60 fps

    def _step(self):
        self._progress = min(1.0, self._progress + 0.038)
        if self._progress >= 1.0:
            self._timer.stop()
        self.update()

    # ease-out cubic — fast start, smooth stop
    @staticmethod
    def _ease(t):
        return 1 - (1 - t) ** 3

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        ring_w = 15
        margin = ring_w + 8
        rect = QRectF(margin, margin, w - margin * 2, h - margin * 2)

        total = self._target_clean + self._target_malware
        eased = self._ease(self._progress)

        # Background ring
        pen = QPen(QColor("#21262D"))
        pen.setWidth(ring_w)
        pen.setCapStyle(Qt.FlatCap)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(rect)

        if total == 0:
            # Empty placeholder ring
            pen = QPen(QColor("#30363D"))
            pen.setWidth(ring_w)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawArc(rect, int(91 * 16), int(-358 * 16))
        else:
            malware_ratio = self._target_malware / total
            clean_ratio   = self._target_clean   / total
            sweep_total   = 360 * eased
            start         = 90   # 12 o'clock

            # Malware arc (red) — drawn first
            malware_sweep = malware_ratio * sweep_total
            if malware_sweep > 0.5:
                pen = QPen(QColor("#F85149"))
                pen.setWidth(ring_w)
                pen.setCapStyle(Qt.RoundCap)
                painter.setPen(pen)
                painter.drawArc(rect,
                    int(start * 16),
                    int(-malware_sweep * 16))

            # Clean arc (green) — follows immediately after red
            clean_sweep = clean_ratio * sweep_total
            if clean_sweep > 0.5:
                clean_start = start - malware_sweep
                pen = QPen(QColor("#3FB950"))
                pen.setWidth(ring_w)
                pen.setCapStyle(Qt.RoundCap)
                painter.setPen(pen)
                painter.drawArc(rect,
                    int(clean_start * 16),
                    int(-clean_sweep * 16))

        # Centre — total count
        cx, cy = w / 2, h / 2
        painter.setPen(QColor("#E6EDF3"))
        painter.setFont(QFont("Segoe UI", 20, QFont.Bold))
        painter.drawText(QRectF(0, cy - 20, w, 28), Qt.AlignCenter, str(total))

        # Centre — label
        painter.setPen(QColor("#8B949E"))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(QRectF(0, cy + 9, w, 16), Qt.AlignCenter, "Total Scans")
