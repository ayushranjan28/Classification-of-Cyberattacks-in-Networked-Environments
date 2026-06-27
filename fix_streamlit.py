import os
from pathlib import Path

dashboard_dir = Path(r'c:\Users\ayush\Desktop\dataport\project\dashboard\views')
for py_file in dashboard_dir.glob('*.py'):
    text = py_file.read_text('utf-8')
    new_text = text.replace('use_container_width=True', 'width="stretch"')
    new_text = new_text.replace('use_container_width=False', 'width="content"')
    if text != new_text:
        py_file.write_text(new_text, 'utf-8')
        print(f'Updated {py_file.name}')
