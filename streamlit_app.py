import streamlit as st
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Read and execute the main file
try:
    with open('dora_analyzer_enhanced.py', 'r', encoding='utf-8') as f:
        exec(f.read(), globals())
except Exception as e:
    st.error(f"Error: {str(e)}")
    st.info("Please ensure dora_analyzer_enhanced.py exists in the repository.")
