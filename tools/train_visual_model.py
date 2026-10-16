#!/usr/bin/env python3
"""
SentinelX Visual CNN Malware Detection Model - Training Script
==============================================================
Trains an EfficientNet-B0 model to classify malware families from
grayscale binary visualization images (256x256 PNGs).

Dataset layout:
  Dataset/Malware_Merge/   -> 39 malware family folders, each with PNGs
  Dataset/Benign/          -> auto-collected benign EXE visualizations

Output:
  models/visual_model.pth   -> trained model state dict
  models/visual_classes.json -> ordered list of class names
"""

import argparse
import json
import logging
import os
import sys
import time
import glob as globmod
from pathlib import Path
from collections import Counter

import numpy as np
from PIL import Image

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from torchvision import transforms, models
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ---------------------------------------------------------------------------
# Paths (defaults, overridable via CLI)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MALWARE_DIR = PROJECT_ROOT / "Dataset" / "Malware_Merge"
DEFAULT_BENIGN_DIR = PROJECT_ROOT / "Dataset" / "Benign"
DEFAULT_MODEL_OUTPUT = PROJECT_ROOT / "models" / "visual_model.pth"
DEFAULT_CLASSES_OUTPUT = PROJECT_ROOT / "models" / "visual_classes.json"
LOG_PATH = PROJECT_ROOT / "logs" / "training_report.log"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(log_path: Path):
    """Configure dual logging to file and console."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("train_visual")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(str(log_path), mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# ---------------------------------------------------------------------------
# Benign sample collector
# ---------------------------------------------------------------------------

def exe_bytes_to_grayscale_png(file_path: str, output_path: str, target_pixels: int = 65536):
    """
    Convert an executable's raw bytes into a 256x256 grayscale PNG.

    Method (matches visual_engine.py):
      - If file < target_pixels bytes: pad with zeros
      - If file > target_pixels bytes: sample evenly (every Nth byte)
      - Reshape to 256x256
    """
    with open(file_path, "rb") as f:
        raw = f.read()

    file_size = len(raw)
    if file_size == 0:
        return False

    byte_array = np.frombuffer(raw, dtype=np.uint8)

    if file_size < target_pixels:
        # Pad with zeros
        padded = np.zeros(target_pixels, dtype=np.uint8)
        padded[:file_size] = byte_array
        byte_array = padded
    elif file_size > target_pixels:
        # Evenly sample to get exactly target_pixels bytes
        indices = np.linspace(0, file_size - 1, target_pixels, dtype=int)
        byte_array = byte_array[indices]

    img_array = byte_array.reshape(256, 256)
    img = Image.fromarray(img_array, mode="L")
    img.save(output_path)
    return True


def collect_benign_samples(benign_dir: Path, logger, target_count: int = 500):
    """
    Scan system directories for EXEs and convert them to grayscale PNGs.
    Targets C:\\Windows\\System32\\*.exe and C:\\Program Files\\**\\*.exe.
    """
    benign_dir.mkdir(parents=True, exist_ok=True)

    # Check how many already exist
    existing = list(benign_dir.glob("*.png"))
    if len(existing) >= 300:
        logger.info(
            f"Benign folder already has {len(existing)} samples, skipping collection."
        )
        return len(existing)

    logger.info("Collecting benign EXE samples from system directories...")

    # Gather EXE paths from system locations
    exe_paths = []

    # C:\Windows\System32\*.exe
    sys32 = r"C:\Windows\System32"
    if os.path.isdir(sys32):
        for f in globmod.glob(os.path.join(sys32, "*.exe")):
            exe_paths.append(f)

    # C:\Program Files\**\*.exe
    pf64 = r"C:\Program Files"
    if os.path.isdir(pf64):
        for f in globmod.glob(os.path.join(pf64, "**", "*.exe"), recursive=True):
            exe_paths.append(f)

    # C:\Program Files (x86)\**\*.exe  (bonus: more samples)
    pf32 = r"C:\Program Files (x86)"
    if os.path.isdir(pf32):
        for f in globmod.glob(os.path.join(pf32, "**", "*.exe"), recursive=True):
            exe_paths.append(f)

    logger.info(f"Found {len(exe_paths)} EXE candidates on disk.")

    # Deduplicate and limit
    exe_paths = list(dict.fromkeys(exe_paths))  # preserve order, remove dupes
    if len(exe_paths) > target_count:
        # Deterministic sampling
        rng = np.random.default_rng(seed=42)
        indices = rng.choice(len(exe_paths), size=target_count, replace=False)
        indices.sort()
        exe_paths = [exe_paths[i] for i in indices]

    collected = len(existing)
    skipped = 0
    for exe_path in exe_paths:
        if collected >= target_count:
            break
        try:
            fname = os.path.basename(exe_path).replace(" ", "_")
            out_name = f"benign_{collected:04d}_{fname}.png"
            out_path = str(benign_dir / out_name)
            if exe_bytes_to_grayscale_png(exe_path, out_path):
                collected += 1
            else:
                skipped += 1
        except (PermissionError, OSError):
            skipped += 1
            continue

    logger.info(
        f"Benign collection done: {collected} saved, {skipped} skipped (access denied / empty)."
    )
    return collected


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class MalwareVisualDataset(Dataset):
    """PyTorch dataset for malware family grayscale PNG images."""

    def __init__(self, image_paths, labels, transform=None):
        self.image_paths = image_paths
        self.labels = labels
        self.transform = transform

    def __len__(self):
        return len(self.image_paths)

    def __getitem__(self, idx):
        img_path = self.image_paths[idx]
        label = self.labels[idx]

        # Load grayscale and convert to 3-channel (for pretrained EfficientNet)
        img = Image.open(img_path).convert("L")
        img = img.resize((224, 224), Image.BILINEAR)

        # Convert to 3-channel by repeating
        img_np = np.array(img, dtype=np.uint8)
        img_rgb = np.stack([img_np, img_np, img_np], axis=2)
        img = Image.fromarray(img_rgb, mode="RGB")

        if self.transform:
            img = self.transform(img)

        return img, label


def load_dataset(malware_dir: Path, benign_dir: Path, logger):
    """
    Load all image paths and labels from malware family folders and benign folder.
    Returns: image_paths, labels (int), class_names (list[str])
    """
    image_paths = []
    label_names = []

    # --- Malware families ---
    if not malware_dir.is_dir():
        logger.error(f"Malware dataset directory not found: {malware_dir}")
        sys.exit(1)

    family_dirs = sorted(
        [d for d in malware_dir.iterdir() if d.is_dir()], key=lambda d: d.name
    )
    logger.info(f"Found {len(family_dirs)} malware family folders.")

    for fdir in family_dirs:
        pngs = list(fdir.glob("*.png"))
        if not pngs:
            logger.warning(f"  {fdir.name}: no PNG files, skipping.")
            continue
        for p in pngs:
            image_paths.append(str(p))
            label_names.append(fdir.name)
        logger.info(f"  {fdir.name}: {len(pngs)} images")

    # --- Benign ---
    if benign_dir.is_dir():
        pngs = list(benign_dir.glob("*.png"))
        if pngs:
            for p in pngs:
                image_paths.append(str(p))
                label_names.append("Benign")
            logger.info(f"  Benign: {len(pngs)} images")
        else:
            logger.warning("Benign folder exists but contains no PNGs.")
    else:
        logger.warning(f"Benign folder not found: {benign_dir}")

    # Build class index
    class_names = sorted(set(label_names))
    class_to_idx = {name: i for i, name in enumerate(class_names)}
    labels = [class_to_idx[n] for n in label_names]

    logger.info(f"Total images: {len(image_paths)}, Total classes: {len(class_names)}")
    return image_paths, labels, class_names


# ---------------------------------------------------------------------------
# Model builder
# ---------------------------------------------------------------------------

def build_model(num_classes: int, device: torch.device):
    """Build EfficientNet-B0 with custom classifier head."""
    weights = models.EfficientNet_B0_Weights.IMAGENET1K_V1
    model = models.efficientnet_b0(weights=weights)

    # Freeze all feature layers initially
    for param in model.features.parameters():
        param.requires_grad = False

    # Replace classifier
    model.classifier = nn.Sequential(
        nn.Dropout(0.2),
        nn.Linear(1280, 256),
        nn.ReLU(),
        nn.Linear(256, num_classes),
    )

    model = model.to(device)
    return model


def unfreeze_last_blocks(model, num_blocks: int = 2, logger=None):
    """Unfreeze the last N blocks of EfficientNet features for fine-tuning."""
    total_blocks = len(model.features)
    for i in range(total_blocks - num_blocks, total_blocks):
        for param in model.features[i].parameters():
            param.requires_grad = True
    if logger:
        logger.info(
            f"Unfroze last {num_blocks} feature blocks "
            f"(blocks {total_blocks - num_blocks} to {total_blocks - 1}) for fine-tuning."
        )


# ---------------------------------------------------------------------------
# Training utilities
# ---------------------------------------------------------------------------

def compute_class_weights(labels, num_classes, device):
    """Compute inverse-frequency class weights for CrossEntropyLoss."""
    counts = Counter(labels)
    total = len(labels)
    weights = []
    for c in range(num_classes):
        n = counts.get(c, 1)
        weights.append(total / (num_classes * n))
    w = torch.tensor(weights, dtype=torch.float32, device=device)
    return w


def progress_bar(iterable, total, desc="", disable=False):
    """Wrap iterable with tqdm if available, otherwise plain iteration with prints."""
    if HAS_TQDM and not disable:
        return tqdm(iterable, total=total, desc=desc, ncols=100, leave=False)
    else:
        return iterable


def train_one_epoch(model, loader, criterion, optimizer, device, epoch_str=""):
    """Train for one epoch. Returns average loss and accuracy."""
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0

    iterator = progress_bar(loader, total=len(loader), desc=f"Train {epoch_str}")
    for images, labels in iterator:
        images = images.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        running_loss += loss.item() * images.size(0)
        _, predicted = outputs.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)

    avg_loss = running_loss / total
    accuracy = 100.0 * correct / total
    return avg_loss, accuracy


@torch.no_grad()
def validate(model, loader, criterion, device, epoch_str=""):
    """Validate model. Returns average loss, accuracy, all predictions and true labels."""
    model.eval()
    running_loss = 0.0
    correct = 0
    total = 0
    all_preds = []
    all_labels = []

    iterator = progress_bar(loader, total=len(loader), desc=f"Val   {epoch_str}")
    for images, labels in iterator:
        images = images.to(device)
        labels = labels.to(device)

        outputs = model(images)
        loss = criterion(outputs, labels)

        running_loss += loss.item() * images.size(0)
        _, predicted = outputs.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)

        all_preds.extend(predicted.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

    avg_loss = running_loss / total
    accuracy = 100.0 * correct / total
    return avg_loss, accuracy, np.array(all_preds), np.array(all_labels)


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Train SentinelX Visual CNN malware classifier (EfficientNet-B0)"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(DEFAULT_MALWARE_DIR),
        help="Path to malware dataset (default: Dataset/Malware_Merge)",
    )
    parser.add_argument(
        "--benign",
        type=str,
        default=str(DEFAULT_BENIGN_DIR),
        help="Path to benign folder (default: Dataset/Benign, auto-collected if missing)",
    )
    parser.add_argument(
        "--epochs", type=int, default=15, help="Number of training epochs (default: 15)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=32, help="Batch size (default: 32)"
    )
    parser.add_argument(
        "--lr", type=float, default=0.001, help="Learning rate (default: 0.001)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_MODEL_OUTPUT),
        help="Model output path (default: models/visual_model.pth)",
    )
    args = parser.parse_args()

    malware_dir = Path(args.dataset)
    benign_dir = Path(args.benign)
    model_output = Path(args.output)
    classes_output = model_output.parent / "visual_classes.json"
    num_epochs = args.epochs
    batch_size = args.batch_size
    lr = args.lr

    # Setup
    logger = setup_logging(LOG_PATH)
    logger.info("=" * 70)
    logger.info("SentinelX Visual CNN Training Script")
    logger.info("=" * 70)
    logger.info(f"Malware dataset : {malware_dir}")
    logger.info(f"Benign folder   : {benign_dir}")
    logger.info(f"Epochs          : {num_epochs}")
    logger.info(f"Batch size      : {batch_size}")
    logger.info(f"Learning rate   : {lr}")
    logger.info(f"Model output    : {model_output}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device          : {device}")
    if device.type == "cuda":
        logger.info(f"GPU             : {torch.cuda.get_device_name(0)}")

    # -----------------------------------------------------------------------
    # Step 1: Collect benign samples if needed
    # -----------------------------------------------------------------------
    if not benign_dir.is_dir() or len(list(benign_dir.glob("*.png"))) < 10:
        logger.info("-" * 70)
        logger.info("STEP 1: Collecting benign samples")
        logger.info("-" * 70)
        collect_benign_samples(benign_dir, logger, target_count=500)
    else:
        logger.info(
            f"Benign folder exists with {len(list(benign_dir.glob('*.png')))} images."
        )

    # -----------------------------------------------------------------------
    # Step 2: Load dataset
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 2: Loading dataset")
    logger.info("-" * 70)
    image_paths, labels, class_names = load_dataset(malware_dir, benign_dir, logger)
    num_classes = len(class_names)

    if num_classes < 2:
        logger.error("Need at least 2 classes to train. Aborting.")
        sys.exit(1)

    # Save class names
    classes_output.parent.mkdir(parents=True, exist_ok=True)
    with open(str(classes_output), "w", encoding="utf-8") as f:
        json.dump(class_names, f, indent=2)
    logger.info(f"Saved {num_classes} class names to {classes_output}")

    # -----------------------------------------------------------------------
    # Step 3: Stratified train/val split
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 3: Splitting dataset (80/20 stratified)")
    logger.info("-" * 70)
    train_paths, val_paths, train_labels, val_labels = train_test_split(
        image_paths, labels, test_size=0.2, random_state=42, stratify=labels
    )
    logger.info(f"Training samples  : {len(train_paths)}")
    logger.info(f"Validation samples: {len(val_paths)}")

    # -----------------------------------------------------------------------
    # Step 4: Data transforms and loaders
    # -----------------------------------------------------------------------
    train_transform = transforms.Compose([
        transforms.RandomHorizontalFlip(),
        transforms.RandomRotation(5),
        transforms.ToTensor(),
        transforms.Normalize(
            mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]
        ),
    ])
    val_transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(
            mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]
        ),
    ])

    train_dataset = MalwareVisualDataset(train_paths, train_labels, train_transform)
    val_dataset = MalwareVisualDataset(val_paths, val_labels, val_transform)

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
        pin_memory=(device.type == "cuda"),
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
        pin_memory=(device.type == "cuda"),
    )

    # -----------------------------------------------------------------------
    # Step 5: Build model, loss, optimizer
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 4: Building model (EfficientNet-B0)")
    logger.info("-" * 70)
    model = build_model(num_classes, device)

    class_weights = compute_class_weights(train_labels, num_classes, device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    # Only classifier params are trainable initially
    optimizer = optim.Adam(
        filter(lambda p: p.requires_grad, model.parameters()), lr=lr
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"Total parameters     : {total_params:,}")
    logger.info(f"Trainable parameters : {trainable:,}")

    # -----------------------------------------------------------------------
    # Step 6: Training loop
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 5: Training")
    logger.info("-" * 70)

    best_val_acc = 0.0
    best_epoch = 0
    best_state = None
    start_time = time.time()

    try:
        for epoch in range(1, num_epochs + 1):
            epoch_start = time.time()

            # Unfreeze last 2 blocks after epoch 5 for fine-tuning
            if epoch == 6:
                unfreeze_last_blocks(model, num_blocks=2, logger=logger)
                # Rebuild optimizer with differential learning rates
                feature_params = []
                classifier_params = []
                for name, param in model.named_parameters():
                    if param.requires_grad:
                        if "classifier" in name:
                            classifier_params.append(param)
                        else:
                            feature_params.append(param)
                optimizer = optim.Adam([
                    {"params": feature_params, "lr": lr / 10},
                    {"params": classifier_params, "lr": lr},
                ])
                logger.info(
                    f"Fine-tuning: feature lr={lr/10:.6f}, classifier lr={lr:.6f}"
                )

            epoch_str = f"[{epoch}/{num_epochs}]"

            train_loss, train_acc = train_one_epoch(
                model, train_loader, criterion, optimizer, device, epoch_str
            )
            val_loss, val_acc, val_preds, val_true = validate(
                model, val_loader, criterion, device, epoch_str
            )

            epoch_time = time.time() - epoch_start

            logger.info(
                f"Epoch {epoch_str} | "
                f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.1f}% | "
                f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.1f}% | "
                f"Time: {epoch_time:.1f}s"
            )

            # Save best model
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_epoch = epoch
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                logger.info(
                    f"  >> New best model! Val Acc: {val_acc:.1f}% (epoch {epoch})"
                )

    except KeyboardInterrupt:
        logger.info("\nTraining interrupted by user.")
        logger.info("Saving best model so far...")

    total_time = time.time() - start_time

    # -----------------------------------------------------------------------
    # Step 7: Save best model
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 6: Saving model")
    logger.info("-" * 70)

    if best_state is not None:
        model_output.parent.mkdir(parents=True, exist_ok=True)
        torch.save(best_state, str(model_output))
        model_size_mb = os.path.getsize(str(model_output)) / (1024 * 1024)
        logger.info(f"Best model saved to: {model_output}")
        logger.info(f"  Best epoch    : {best_epoch}")
        logger.info(f"  Best val acc  : {best_val_acc:.1f}%")
        logger.info(f"  Model size    : {model_size_mb:.1f} MB")
    else:
        logger.warning("No model was saved (training did not complete any epoch).")
        model_size_mb = 0

    # -----------------------------------------------------------------------
    # Step 8: Final evaluation and per-class report
    # -----------------------------------------------------------------------
    logger.info("-" * 70)
    logger.info("STEP 7: Final evaluation (per-class report)")
    logger.info("-" * 70)

    if best_state is not None:
        # Load best model for final eval
        model.load_state_dict(best_state)
        model = model.to(device)
        _, final_acc, final_preds, final_true = validate(
            model, val_loader, criterion, device, "final"
        )

        # Per-class accuracy from confusion matrix
        cm = confusion_matrix(final_true, final_preds, labels=list(range(num_classes)))
        logger.info(f"\n{'Class':<30s} {'Samples':>8s} {'Correct':>8s} {'Accuracy':>10s}")
        logger.info("-" * 58)
        for i, cname in enumerate(class_names):
            row_total = cm[i].sum()
            row_correct = cm[i][i]
            acc = 100.0 * row_correct / row_total if row_total > 0 else 0.0
            logger.info(f"{cname:<30s} {row_total:>8d} {row_correct:>8d} {acc:>9.1f}%")
        logger.info("-" * 58)

        # Classification report (precision, recall, f1)
        report = classification_report(
            final_true, final_preds,
            target_names=class_names,
            digits=3,
            zero_division=0,
        )
        logger.info(f"\nClassification Report:\n{report}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    logger.info("=" * 70)
    logger.info("TRAINING SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total training time : {total_time/60:.1f} minutes ({total_time:.0f}s)")
    logger.info(f"Best epoch          : {best_epoch}")
    logger.info(f"Best val accuracy   : {best_val_acc:.1f}%")
    logger.info(f"Number of classes   : {num_classes}")
    logger.info(f"Model output        : {model_output}")
    logger.info(f"Classes file        : {classes_output}")
    if best_state is not None:
        logger.info(f"Model size          : {model_size_mb:.1f} MB")
    logger.info(f"Training log        : {LOG_PATH}")
    logger.info("=" * 70)
    logger.info("Done.")


if __name__ == "__main__":
    main()
