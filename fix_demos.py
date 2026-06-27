import os
from pathlib import Path
import re

demo_dir = Path(r'c:\Users\ayush\Desktop\dataport\project\demo')
for py_file in demo_dir.glob('sim_*.py'):
    text = py_file.read_text('utf-8')
    if 'insert_flow(' in text and 'explanation=' not in text:
        new_text = re.sub(r'(features\s*=\s*)', r'explanation="Simulated attack.",\n                \1', text)
        if new_text != text:
            py_file.write_text(new_text, 'utf-8')
            print(f'Updated {py_file.name}')
