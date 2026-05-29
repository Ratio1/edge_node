#!/usr/bin/env python3
import multiprocessing as mp
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from naeural_core.main.entrypoint import main


if __name__ == "__main__":
  mp.set_start_method("spawn")
  exit_code, _ = main()
  os._exit(exit_code)
