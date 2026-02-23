import os
import PyInstaller.__main__
import shutil

print("Building SentinelX Standalone Executable...")

# Clean previous builds
if os.path.exists('build'):
    shutil.rmtree('build')
if os.path.exists('dist'):
    shutil.rmtree('dist')

PyInstaller.__main__.run([
    'main.py',
    '--name=SentinelX',
    '--windowed',
    '--add-data=rules;rules',
    '--add-data=models;models',
    '--hidden-import=sklearn.utils._typedefs',
    '--hidden-import=sklearn.neighbors._partition_nodes',
    '--hidden-import=yara',
    '--hidden-import=sqlite3',
    '--clean',
    '--noconfirm'
])

print("\n==================================")
print("Build Complete! Check the /dist/SentinelX directory.")
print("Run SentinelX.exe to start the application.")
print("==================================")
