"""
  ⚠️ do not modify this ⚠️
"""

import multiprocessing as mp
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from naeural_core.main.entrypoint import main
  
  
if __name__ == '__main__':  
  mp.set_start_method('spawn') # if moved at import will generate errors in subprocs
  exit_code, eng = main(
    additional_packages=['llama-cpp-python'],
  )
  
  # TODO: configured with flag in startup
  SYS_EXIT = False 
  
  if SYS_EXIT:
    print("Executing sys.exit({})...".format(exit_code))
    sys.exit(exit_code)
  else:
    print("Executing os._exit({})...".format(exit_code))
    os._exit(exit_code)
  #endif sys exit
  
