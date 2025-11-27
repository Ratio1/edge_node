def format_memory_to_standard(self, memory_value):
  """
  Convert memory value to standard format (string with unit).
  Supports: "4096m", "4g", "4096", 4096

  Args:
      memory_value: Memory value as string or int

  Returns:
      str: Standardized memory string (e.g., "4096m")
  """
  if memory_value is None:
    return None

  # If already a string with unit, return as-is
  if isinstance(memory_value, str):
    if memory_value.endswith(('m', 'M', 'g', 'G', 'k', 'K')):
      return memory_value.lower()
    # String number without unit - assume bytes, convert to MB
    try:
      bytes_value = int(memory_value)
      return f"{bytes_value // (1024 * 1024)}m"
    except ValueError:
      return memory_value

  # If integer, assume bytes and convert to MB
  if isinstance(memory_value, int):
    return f"{memory_value // (1024 * 1024)}m"

  return str(memory_value)


def parse_memory_to_mb(memory_str, scaling_factor: float = 0.0):
  """
  Parse memory string to megabytes.

  Args:
      memory_str: Memory value like "4096m", "4g", "128m"

  Returns:
      int: Memory in megabytes
  """
  if memory_str is None:
    return 0

  memory_str = str(memory_str).lower().strip()

  # Extract number and unit
  import re
  match = re.match(r'^(\d+(?:\.\d+)?)\s*([bkmg]?)$', memory_str)
  if not match:
    # Try to parse as plain number (assume MB)
    try:
      return int(float(memory_str))
    except ValueError:
      return 0

  value = float(match.group(1))
  unit = match.group(2)

  if scaling_factor:
    value = value * scaling_factor

  # Convert to MB
  if unit == 'b':
    return int(value / 1024 / 1000)
  elif unit == 'k':
    return int(value / 1024)
  elif unit == 'm' or unit == '':
    return int(value)
  elif unit == 'g':
    return int(value * 1024)

  return 0

if __name__=="__main__":
  mem_samples = ["2000k", "512m", "1g"]
  for mem_sample in mem_samples:
    converted = parse_memory_to_mb(mem_sample, 0.9)
    print(f"{mem_sample} -> {converted}")
