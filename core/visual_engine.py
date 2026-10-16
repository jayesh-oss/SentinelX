"""
Visual Malware Detection Engine for SentinelX
CNN-based malware classification using binary-to-image conversion and EfficientNet-B0.
"""

import os
import io
import json
import glob
import logging
import math
import struct
import threading
from datetime import datetime
from pathlib import Path

import numpy as np
from PIL import Image

# --------------------------------------------------------------------------- #
# Optional torch / torchvision imports                                        #
# --------------------------------------------------------------------------- #
TORCH_AVAILABLE = False
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
    from torchvision import models, transforms
    from torchvision.models import EfficientNet_B0_Weights
    TORCH_AVAILABLE = True
except ImportError:
    pass

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #
IMAGE_SIZE = 256          # binary -> 256x256 grayscale
MODEL_INPUT_SIZE = 224    # EfficientNet input
PIXEL_COUNT = IMAGE_SIZE * IMAGE_SIZE  # 65 536

MALWARE_FAMILIES = [
    "Adialer.C", "Agent.FYI", "Allaple.A", "Allaple.L", "Alueron.gen!J",
    "Autorun.K", "C2LOP.P", "C2LOP.gen!g", "CoinMinerXMRig", "Danabot",
    "Dialplatform.B", "Dontovo.A", "Dridex", "Fakerean", "Gh0stRAT",
    "Glupteba", "Gozi", "Instantaccess", "Lolyda.AA1", "Lolyda.AA2",
    "Lolyda.AA3", "Lolyda.AT", "Malex.gen!J", "NanoCore", "Obfuscator.AD",
    "Quakbot", "Rbot!gen", "RecordBreaker", "RedLineStealer", "Remcos",
    "Skintrim.N", "Swizzor.gen!E", "Swizzor.gen!I", "Tinba", "Trickbot",
    "VB.AT", "Wintrim.BX", "Yuner.A", "Zeus",
]

CLASS_NAMES = MALWARE_FAMILIES + ["Benign"]  # 40 classes total
NUM_CLASSES = len(CLASS_NAMES)

# --------------------------------------------------------------------------- #
# Logging helpers                                                              #
# --------------------------------------------------------------------------- #
_log_lock = threading.Lock()


def _get_logger(name: str, log_file: str) -> logging.Logger:
    """Return a named logger that writes to *log_file* (created if absent)."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# --------------------------------------------------------------------------- #
# Binary-to-image conversion                                                   #
# --------------------------------------------------------------------------- #

def binary_to_image(file_data: bytes) -> Image.Image:
    """Convert raw file bytes into a 256x256 grayscale PIL Image.

    - Files smaller than 65 536 bytes are zero-padded at the end.
    - Files larger than 65 536 bytes are evenly sampled (stride-based)
      so that exactly 65 536 bytes are kept.
    """
    data_len = len(file_data)

    if data_len == 0:
        pixel_bytes = b"\x00" * PIXEL_COUNT
    elif data_len <= PIXEL_COUNT:
        pixel_bytes = file_data + b"\x00" * (PIXEL_COUNT - data_len)
    else:
        # Evenly sample PIXEL_COUNT bytes from the file
        indices = np.linspace(0, data_len - 1, PIXEL_COUNT, dtype=np.int64)
        arr = np.frombuffer(file_data, dtype=np.uint8)
        pixel_bytes = arr[indices].tobytes()

    img = Image.frombytes("L", (IMAGE_SIZE, IMAGE_SIZE), pixel_bytes)
    return img


# --------------------------------------------------------------------------- #
# Image preprocessing                                                          #
# --------------------------------------------------------------------------- #

def preprocess_image(img: Image.Image) -> "torch.Tensor":
    """Prepare a 256x256 grayscale PIL Image for EfficientNet inference.

    - Duplicates the single channel to 3 channels (RGB).
    - Resizes to 224x224.
    - Normalizes with ImageNet mean / std.
    - Returns a tensor of shape (1, 3, 224, 224).
    """
    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch is not installed.")

    # Ensure grayscale
    if img.mode != "L":
        img = img.convert("L")

    # Duplicate to 3 channels
    img_rgb = Image.merge("RGB", (img, img, img))

    transform = transforms.Compose([
        transforms.Resize((MODEL_INPUT_SIZE, MODEL_INPUT_SIZE)),
        transforms.ToTensor(),  # -> [3, 224, 224], range [0, 1]
        transforms.Normalize(
            mean=[0.485, 0.456, 0.406],
            std=[0.229, 0.224, 0.225],
        ),
    ])

    tensor = transform(img_rgb)          # (3, 224, 224)
    tensor = tensor.unsqueeze(0)         # (1, 3, 224, 224)
    return tensor


# --------------------------------------------------------------------------- #
# Custom dataset for training                                                  #
# --------------------------------------------------------------------------- #

class _MalwareImageDataset(Dataset):
    """Simple image-folder dataset where each subfolder is a class."""

    def __init__(self, samples: list, class_to_idx: dict, transform=None):
        """
        Parameters
        ----------
        samples : list of (path, class_index)
        class_to_idx : dict  class_name -> int
        transform : torchvision transform
        """
        self.samples = samples
        self.class_to_idx = class_to_idx
        self.transform = transform

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        img = Image.open(path).convert("L")
        # Duplicate to 3-channel
        img_rgb = Image.merge("RGB", (img, img, img))
        if self.transform:
            img_rgb = self.transform(img_rgb)
        return img_rgb, label


# --------------------------------------------------------------------------- #
# VisualMLEngine                                                               #
# --------------------------------------------------------------------------- #

class VisualMLEngine:
    """CNN-based visual malware classifier using EfficientNet-B0."""

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, "visual_model.pth")
        self.classes_path = os.path.join(model_dir, "visual_classes.json")
        self.device = torch.device("cpu") if TORCH_AVAILABLE else None
        self.class_names = list(CLASS_NAMES)  # copy
        self.model = None
        self._lock = threading.Lock()

        # Set up loggers
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._test_logger = _get_logger(
            "sentinelx.visual.test",
            os.path.join(base_dir, "logs", "testing_report.log"),
        )
        self._train_logger = _get_logger(
            "sentinelx.visual.train",
            os.path.join(base_dir, "logs", "training_report.log"),
        )

        if not TORCH_AVAILABLE:
            self._test_logger.warning(
                "PyTorch/torchvision not installed. Visual engine unavailable."
            )
            return

        # Try to load saved class names first (they may differ from defaults)
        if os.path.isfile(self.classes_path):
            try:
                with open(self.classes_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, list) and len(loaded) > 0:
                    self.class_names = loaded
            except Exception:
                pass

        # Attempt to load the trained model
        if os.path.isfile(self.model_path):
            success = self._load_model()
            if not success:
                self._test_logger.warning(
                    "Failed to load visual model from %s", self.model_path
                )
        else:
            self._test_logger.warning(
                "Visual model not found at %s. Run training first.",
                self.model_path,
            )

    # ------------------------------------------------------------------ #
    # Model building / loading                                            #
    # ------------------------------------------------------------------ #

    def _build_model(self, num_classes: int = NUM_CLASSES) -> "nn.Module":
        """Build the EfficientNet-B0 architecture with a custom classifier."""
        model = models.efficientnet_b0(weights=None)
        model.classifier = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(1280, 256),
            nn.ReLU(),
            nn.Linear(256, num_classes),
        )
        return model

    def _load_model(self) -> bool:
        """Load the trained model weights from disk."""
        try:
            num_classes = len(self.class_names)
            model = self._build_model(num_classes=num_classes)
            state_dict = torch.load(
                self.model_path, map_location="cpu", weights_only=False
            )
            model.load_state_dict(state_dict)
            model.to(self.device)
            model.eval()
            self.model = model
            self._test_logger.info(
                "Visual model loaded successfully (%d classes).", num_classes
            )
            return True
        except Exception as exc:
            self._test_logger.error("Error loading visual model: %s", exc)
            self.model = None
            return False

    # ------------------------------------------------------------------ #
    # Prediction                                                          #
    # ------------------------------------------------------------------ #

    def predict(self, file_data: bytes) -> dict:
        """Run malware classification on raw file bytes.

        Returns a dict with keys:
            score, family, confidence, available, top3, grayscale_png
        """
        if not TORCH_AVAILABLE or self.model is None:
            return {
                "score": 0.0,
                "family": "Unknown",
                "confidence": 0.0,
                "available": False,
            }

        img = binary_to_image(file_data)
        result = self._predict_from_image(img, file_size=len(file_data))

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        result["grayscale_png"] = buf.getvalue()

        return result

    def predict_image(self, img: Image.Image) -> dict:
        """Run malware classification on an already-prepared PIL Image."""
        if not TORCH_AVAILABLE or self.model is None:
            return {
                "score": 0.0,
                "family": "Unknown",
                "confidence": 0.0,
                "available": False,
            }

        return self._predict_from_image(img, file_size=None)

    def _predict_from_image(self, img: Image.Image, file_size=None) -> dict:
        """Internal helper shared by predict() and predict_image()."""
        tensor = preprocess_image(img)
        tensor = tensor.to(self.device)

        with torch.no_grad():
            logits = self.model(tensor)              # (1, num_classes)
            probs = torch.softmax(logits, dim=1)[0]  # (num_classes,)

        probs_np = probs.cpu().numpy()

        # Top prediction
        top_idx = int(probs_np.argmax())
        top_confidence = float(probs_np[top_idx])
        predicted_family = self.class_names[top_idx]

        # Top-3 predictions
        top3_indices = probs_np.argsort()[::-1][:3]
        top3 = [
            {"name": self.class_names[int(i)], "confidence": float(probs_np[i])}
            for i in top3_indices
        ]

        # Malware score
        benign_idx = (
            self.class_names.index("Benign")
            if "Benign" in self.class_names
            else None
        )

        if predicted_family == "Benign" and benign_idx is not None:
            malware_score = 1.0 - float(probs_np[benign_idx])
        else:
            # Sum of all non-benign probabilities
            if benign_idx is not None:
                malware_score = float(1.0 - probs_np[benign_idx])
            else:
                malware_score = float(top_confidence)

        malware_score = max(0.0, min(1.0, malware_score))

        # Log
        with _log_lock:
            self._test_logger.info(
                "Prediction | file_size=%s | class=%s | confidence=%.4f "
                "| malware_score=%.4f | top3=%s",
                file_size if file_size is not None else "image_input",
                predicted_family,
                top_confidence,
                malware_score,
                json.dumps(top3),
            )

        return {
            "score": malware_score,
            "family": predicted_family,
            "confidence": top_confidence,
            "available": True,
            "top3": top3,
        }

    # ------------------------------------------------------------------ #
    # Utility: grayscale image bytes for UI preview                       #
    # ------------------------------------------------------------------ #

    def get_grayscale_image_bytes(self, file_data: bytes) -> bytes:
        """Return a PNG-encoded grayscale visualisation of the binary."""
        img = binary_to_image(file_data)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    # ------------------------------------------------------------------ #
    # Training                                                            #
    # ------------------------------------------------------------------ #

    def train(
        self,
        dataset_dir: str,
        benign_dir: str = None,
        epochs: int = 15,
        batch_size: int = 32,
        lr: float = 0.001,
    ) -> dict:
        """Train (or retrain) the visual malware classifier.

        Parameters
        ----------
        dataset_dir : str
            Root of the MaleBin-style dataset. Each subfolder is one
            malware family containing 256x256 grayscale PNGs.
        benign_dir : str, optional
            Folder of benign PE images. If *None*, benign samples are
            collected automatically from System32 / Program Files.
        epochs : int
        batch_size : int
        lr : float

        Returns
        -------
        dict  Training history with lists of per-epoch metrics.
        """
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch is not installed. Cannot train.")

        self._train_logger.info("=" * 70)
        self._train_logger.info("Training started at %s", datetime.now().isoformat())
        self._train_logger.info(
            "dataset_dir=%s | benign_dir=%s | epochs=%d | batch_size=%d | lr=%s",
            dataset_dir, benign_dir, epochs, batch_size, lr,
        )

        # -------- collect samples -------- #
        samples = []     # list of (path, class_name)
        class_counts = {}

        # Malware families from the dataset directory
        for family_name in sorted(os.listdir(dataset_dir)):
            family_path = os.path.join(dataset_dir, family_name)
            if not os.path.isdir(family_path):
                continue
            imgs = (
                glob.glob(os.path.join(family_path, "*.png"))
                + glob.glob(os.path.join(family_path, "*.PNG"))
                + glob.glob(os.path.join(family_path, "*.jpg"))
                + glob.glob(os.path.join(family_path, "*.jpeg"))
            )
            for p in imgs:
                samples.append((p, family_name))
            class_counts[family_name] = len(imgs)
            self._train_logger.info(
                "  Family %-25s : %d samples", family_name, len(imgs)
            )

        # Benign samples
        benign_samples = self._collect_benign_samples(benign_dir)
        for p in benign_samples:
            samples.append((p, "Benign"))
        class_counts["Benign"] = len(benign_samples)
        self._train_logger.info(
            "  Family %-25s : %d samples", "Benign", len(benign_samples)
        )

        if len(samples) == 0:
            raise ValueError("No samples found. Check dataset_dir path.")

        # -------- class index mapping -------- #
        present_classes = sorted(set(name for _, name in samples))
        class_to_idx = {name: i for i, name in enumerate(present_classes)}
        num_classes = len(present_classes)
        self.class_names = present_classes
        self._train_logger.info("Total classes: %d | Total samples: %d",
                                num_classes, len(samples))

        # -------- stratified train / val split (80/20) -------- #
        from collections import defaultdict
        import random

        random.seed(42)
        per_class: dict = defaultdict(list)
        for path, cname in samples:
            per_class[cname].append((path, class_to_idx[cname]))

        train_samples, val_samples = [], []
        for cname, items in per_class.items():
            random.shuffle(items)
            split = max(1, int(len(items) * 0.8))
            train_samples.extend(items[:split])
            val_samples.extend(items[split:])

        random.shuffle(train_samples)
        random.shuffle(val_samples)
        self._train_logger.info(
            "Train samples: %d | Val samples: %d",
            len(train_samples), len(val_samples),
        )

        # -------- transforms -------- #
        train_transform = transforms.Compose([
            transforms.Resize((MODEL_INPUT_SIZE, MODEL_INPUT_SIZE)),
            transforms.RandomHorizontalFlip(),
            transforms.RandomRotation(5),
            transforms.ColorJitter(brightness=0.1, contrast=0.1),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406],
                                 [0.229, 0.224, 0.225]),
        ])

        val_transform = transforms.Compose([
            transforms.Resize((MODEL_INPUT_SIZE, MODEL_INPUT_SIZE)),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406],
                                 [0.229, 0.224, 0.225]),
        ])

        train_ds = _MalwareImageDataset(train_samples, class_to_idx, train_transform)
        val_ds = _MalwareImageDataset(val_samples, class_to_idx, val_transform)

        # -------- class weights for imbalanced data -------- #
        train_labels = [label for _, label in train_samples]
        label_counts = np.bincount(train_labels, minlength=num_classes).astype(np.float64)
        label_counts = np.maximum(label_counts, 1.0)  # avoid division by zero
        class_weights = 1.0 / label_counts
        class_weights = class_weights / class_weights.sum() * num_classes
        class_weights_tensor = torch.tensor(class_weights, dtype=torch.float32)

        # Weighted sampler so each batch is roughly balanced
        sample_weights = [class_weights[label] for _, label in train_samples]
        sampler = WeightedRandomSampler(
            weights=sample_weights,
            num_samples=len(train_samples),
            replacement=True,
        )

        train_loader = DataLoader(
            train_ds, batch_size=batch_size, sampler=sampler,
            num_workers=0, pin_memory=False,
        )
        val_loader = DataLoader(
            val_ds, batch_size=batch_size, shuffle=False,
            num_workers=0, pin_memory=False,
        )

        # -------- build model with pretrained weights -------- #
        model = models.efficientnet_b0(weights=EfficientNet_B0_Weights.DEFAULT)
        model.classifier = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(1280, 256),
            nn.ReLU(),
            nn.Linear(256, num_classes),
        )
        model.to(self.device)

        # Freeze all feature layers initially
        for param in model.features.parameters():
            param.requires_grad = False

        criterion = nn.CrossEntropyLoss(weight=class_weights_tensor.to(self.device))
        optimizer = optim.Adam(
            filter(lambda p: p.requires_grad, model.parameters()), lr=lr
        )

        # -------- training loop -------- #
        best_val_acc = 0.0
        history = {
            "train_loss": [], "train_acc": [],
            "val_loss": [], "val_acc": [],
        }

        self._train_logger.info("-" * 50)

        for epoch in range(1, epochs + 1):
            # Unfreeze last 2 feature blocks after epoch 5
            if epoch == 6:
                self._train_logger.info(
                    "Epoch %d: Unfreezing last 2 feature blocks for fine-tuning.", epoch
                )
                # EfficientNet features are nn.Sequential of blocks (0..8)
                total_blocks = len(model.features)
                for i in range(max(0, total_blocks - 2), total_blocks):
                    for param in model.features[i].parameters():
                        param.requires_grad = True
                # Lower learning rate for fine-tuning
                optimizer = optim.Adam(
                    filter(lambda p: p.requires_grad, model.parameters()),
                    lr=lr * 0.1,
                )

            # --- Train --- #
            model.train()
            running_loss = 0.0
            correct = 0
            total = 0

            for batch_imgs, batch_labels in train_loader:
                batch_imgs = batch_imgs.to(self.device)
                batch_labels = batch_labels.to(self.device)

                optimizer.zero_grad()
                outputs = model(batch_imgs)
                loss = criterion(outputs, batch_labels)
                loss.backward()
                optimizer.step()

                running_loss += loss.item() * batch_imgs.size(0)
                _, preds = outputs.max(1)
                correct += preds.eq(batch_labels).sum().item()
                total += batch_labels.size(0)

            train_loss = running_loss / max(total, 1)
            train_acc = correct / max(total, 1)

            # --- Validate --- #
            model.eval()
            val_running_loss = 0.0
            val_correct = 0
            val_total = 0
            per_class_correct = np.zeros(num_classes, dtype=np.int64)
            per_class_total = np.zeros(num_classes, dtype=np.int64)

            with torch.no_grad():
                for batch_imgs, batch_labels in val_loader:
                    batch_imgs = batch_imgs.to(self.device)
                    batch_labels = batch_labels.to(self.device)

                    outputs = model(batch_imgs)
                    loss = criterion(outputs, batch_labels)
                    val_running_loss += loss.item() * batch_imgs.size(0)
                    _, preds = outputs.max(1)
                    val_correct += preds.eq(batch_labels).sum().item()
                    val_total += batch_labels.size(0)

                    for i in range(batch_labels.size(0)):
                        lbl = batch_labels[i].item()
                        per_class_total[lbl] += 1
                        if preds[i].item() == lbl:
                            per_class_correct[lbl] += 1

            val_loss = val_running_loss / max(val_total, 1)
            val_acc = val_correct / max(val_total, 1)

            history["train_loss"].append(train_loss)
            history["train_acc"].append(train_acc)
            history["val_loss"].append(val_loss)
            history["val_acc"].append(val_acc)

            self._train_logger.info(
                "Epoch %02d/%02d | train_loss=%.4f | train_acc=%.4f "
                "| val_loss=%.4f | val_acc=%.4f",
                epoch, epochs, train_loss, train_acc, val_loss, val_acc,
            )

            # Per-class accuracy
            for ci in range(num_classes):
                if per_class_total[ci] > 0:
                    cls_acc = per_class_correct[ci] / per_class_total[ci]
                    self._train_logger.info(
                        "    %-25s : %.4f  (%d/%d)",
                        present_classes[ci], cls_acc,
                        int(per_class_correct[ci]), int(per_class_total[ci]),
                    )

            # Save best model
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                os.makedirs(self.model_dir, exist_ok=True)
                torch.save(model.state_dict(), self.model_path)
                with open(self.classes_path, "w", encoding="utf-8") as f:
                    json.dump(present_classes, f, indent=2)
                self._train_logger.info(
                    "  -> New best model saved (val_acc=%.4f)", val_acc
                )

        # Reload the best model
        self.class_names = present_classes
        self._load_model()

        self._train_logger.info("Training complete. Best val_acc=%.4f", best_val_acc)
        self._train_logger.info("=" * 70)

        return history

    # ------------------------------------------------------------------ #
    # Benign sample collection                                            #
    # ------------------------------------------------------------------ #

    def _collect_benign_samples(self, benign_dir: str = None) -> list:
        """Collect benign samples as grayscale PNG images.

        If *benign_dir* points to a folder that already contains images,
        return those paths directly.  Otherwise, harvest PE files from
        System32 / Program Files, convert each to a 256x256 grayscale
        PNG, cache them in a temp "Benign" folder, and return those paths.
        """
        # If a prepared benign image folder was supplied, use it directly
        if benign_dir and os.path.isdir(benign_dir):
            existing = (
                glob.glob(os.path.join(benign_dir, "*.png"))
                + glob.glob(os.path.join(benign_dir, "*.PNG"))
            )
            if existing:
                self._train_logger.info(
                    "Using %d existing benign images from %s",
                    len(existing), benign_dir,
                )
                return existing

        # Auto-collect from Windows system directories
        self._train_logger.info("Collecting benign samples from system directories...")
        pe_paths: list = []

        system32 = r"C:\Windows\System32"
        if os.path.isdir(system32):
            pe_paths.extend(glob.glob(os.path.join(system32, "*.exe")))

        prog_files = r"C:\Program Files"
        if os.path.isdir(prog_files):
            pe_paths.extend(
                glob.glob(os.path.join(prog_files, "**", "*.exe"), recursive=True)
            )

        # Cap to a reasonable number
        max_benign = 500
        if len(pe_paths) > max_benign:
            import random
            random.seed(123)
            random.shuffle(pe_paths)
            pe_paths = pe_paths[:max_benign]

        # Create a temp folder for converted images
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        benign_cache = os.path.join(base_dir, "Dataset", "Benign")
        os.makedirs(benign_cache, exist_ok=True)

        saved_paths = []
        for pe_path in pe_paths:
            try:
                out_name = (
                    os.path.basename(pe_path).replace(".", "_") + ".png"
                )
                out_path = os.path.join(benign_cache, out_name)
                if os.path.isfile(out_path):
                    saved_paths.append(out_path)
                    continue
                with open(pe_path, "rb") as f:
                    raw = f.read()
                img = binary_to_image(raw)
                img.save(out_path, "PNG")
                saved_paths.append(out_path)
            except Exception:
                continue

        self._train_logger.info(
            "Collected %d benign images -> %s", len(saved_paths), benign_cache
        )
        return saved_paths
