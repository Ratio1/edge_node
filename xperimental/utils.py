def color_print(message, color='g', **kwargs):
  """
  color: 'r' (red), 'g' (green), 'y' (yellow), 'd' (gray/default), "w" (white), 'b' (blue)
  """
  colors = {
    'r': '\033[91m',
    'g': '\033[92m',
    'y': '\033[93m',
    'd': '\033[90m',
    'w': '\033[97m',
    'b': '\033[94m',
  }
  endc = '\033[0m'
  color_code = colors.get(color, colors['d'])
  print(f"{color_code}{message}{endc}")
  return