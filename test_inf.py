import joblib
import torch
import numpy as np
import pandas as pd
from pathlib import Path
import sys
sys.path.insert(0, r'c:\Users\ayush\Desktop\dataport\project')
from live_capture.inference import LiveInferenceEngine
engine = LiveInferenceEngine()
print(f'LSTM loaded: {getattr(engine, "lstm_loaded", False)}')
print(f'GNN loaded: {getattr(engine, "gnn_loaded", False)}')

flow_dict = {'Flow Duration': 1000}
res = engine.score_flow(flow_dict, '1.1.1.1', 1234, '2.2.2.2', 80, 'TCP')
print(res)
