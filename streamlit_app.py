# Streamlit Cloud entry point - Direct import
import sys
import os

# Ensure we can find the main file
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Directly execute the main file
exec(open(os.path.join(current_dir, 'dora_analyzer_enhanced.py'), 'r', encoding='utf-8').read())
