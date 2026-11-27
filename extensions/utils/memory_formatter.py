import re
from decimal import Decimal


def size_bytes(value, default_unit="b"):
  """Read a finite capacity in binary units.

  Bare Docker memory values are bytes. Bare Deeploy volume allocations are MiB.

  Parameters
  ----------
  value : str or number
    Stored or signed capacity.
  default_unit : str
    Historical interpretation of a unitless value.

  Returns
  -------
  Decimal
    Exact byte-equivalent amount.

  Examples
  --------
  >>> size_bytes("512m") == size_bytes("0.5g")
  True
  """
  match = re.fullmatch(r"(\d+(?:\.\d+)?|\.\d+)\s*([kmgt]b?|b)?", str(value).strip(), re.I)
  if not match:
    raise ValueError("Invalid container resource size.")
  unit = (match[2] or default_unit)[0].lower()
  amount = Decimal(match[1]) * (1024 ** "bkmgt".index(unit))
  if amount > 2 ** 63 - 1:  # Docker's resource fields are signed 64-bit values.
    raise ValueError("Container resource size exceeds runtime range.")
  return amount


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
