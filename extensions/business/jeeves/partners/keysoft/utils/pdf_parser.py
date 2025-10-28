from typing import List, Optional, Tuple
from copy import deepcopy
from io import BytesIO

import base64
import pdfplumber
import json
import numpy as np

DEFAULT_X_TOLERANCE = 3
DEFAULT_Y_TOLERANCE = 3
DEFAULT_LOOKAHEAD_PX = "auto"
DEFAULT_LOOKAHEAD_PX_VALUE = 12.0

# DEFAULT_TABLE_SETTINGS = {
#   "vertical_strategy": "lines",
#   "horizontal_strategy": "text",
#   "snap_tolerance": 3,
#   "join_tolerance": 3,
#   "edge_min_length": 3,
#   'min_words_horizontal': 2,
#   'intersection_x_tolerance': 8,
# }


class PDFParser:
  def __init__(self):
    return

  def split_header_rows(
      self,
      raw_table: List[List[str]],
  ):
    header_rows = []
    # Identify header rows: continue until a row with no None (or until data likely starts)
    is_header_empty = True
    for row in raw_table:
      is_row_full = all(cell is not None and str(cell).strip() != "" for cell in row)
      if is_header_empty or not is_row_full:
        header_rows.append(row)
        is_header_empty = False
      if is_row_full:
        break
      # endif row eligible for header
    # endfor rows
    raw_data_rows = raw_table[len(header_rows):]
    return header_rows, raw_data_rows

  def compute_header(self, header_rows: List[List[str]]):
    if not header_rows:
      return []
    filled_header = []
    for row in header_rows:
      filled_row = []
      last_val = ""
      for cell in row:
        stripped_cell = str(cell).strip().replace('\n', ' ') if cell is not None else ""
        if cell is None or stripped_cell == "":
          filled_row.append(last_val)
        else:
          filled_row.append(stripped_cell)
          last_val = stripped_cell
      # endfor cells
      filled_header.append(filled_row)
    # endfor rows
    # If multiple header rows, join them with '|'
    if len(filled_header) > 1:
      # Assume last header row contains the leaf column names
      num_cols = len(filled_header[-1])
      headers = []
      for col_idx in range(num_cols):
        parts = []
        for hr in filled_header:
          # Use the header part if it exists and not empty
          if col_idx < len(hr) and hr[col_idx] is not None and str(hr[col_idx]).strip() != "":
            parts.append(hr[col_idx])
        # Join parts with '|' to form multi-level name
        header_name = "|".join(parts) if parts else f"Column{col_idx + 1}"
        headers.append(header_name)
    else:
      # Single header row
      headers = [
        cell if (cell is not None and cell != "") else f"Column{i + 1}"
        for i, cell in enumerate(filled_header[0])
      ]
    # endif multi-row header

    # Make headers unique if needed
    seen = {}
    for i, h in enumerate(headers):
      if h in seen:
        seen[h] += 1
        headers[i] = f"{h}_{seen[h]}"
      else:
        seen[h] = 1
    # endfor headers

    return headers

  def check_nested_structure(self, raw_table: List[List[str]]) -> bool:
    """
    Check for hierarchical nested rows (multiple levels of indentation indicated by blanks)
    Detect if any row has more than one leading blank columns, which suggests nested grouping
    """
    for row in raw_table:
      # Count leading blanks
      blank_prefix = 0
      for cell in row:
        if cell is None or cell == "":
          blank_prefix += 1
        else:
          break
      # endfor cells
      if blank_prefix > 1:  # more than one leading blank implies multi-level grouping
        return True
    # endfor rows
    return False

  def maybe_convert_numeric(self, s):
    if s is None:
      return None
    orig_s = deepcopy(s)
    s = str(s).strip()
    if s == "":
      return None

    s = s.replace(" ", "").replace("\u00A0", "")  # remove spaces and non-breaking spaces
    s = s.replace(",", ".")  # unify decimal point
    parts = [w.strip() for w in s.split(".")]  # split on decimal point
    frac_part = parts[-1] if len(parts) > 1 else None  # last part is fractional if exists
    int_part = "".join(parts[:-1]) if len(parts) > 1 else parts[0]  # rest is integer part
    try:
      if frac_part is not None and frac_part != "":
        val = float(f"{int_part}.{frac_part}")
      else:
        val = int(int_part)
      return val
    except ValueError:
      return orig_s  # return original string if conversion fails

  def __process_table(
      self,
      table_obj: pdfplumber.table.Table,
      page_obj: pdfplumber.page.Page,
      page_number: int,
      table_index: int = 0,
      prev_headers: Optional[List[str]] = None,
      prev_headers_raw: Optional[List[List[str]]] = None,
      prev_table_bbox: Optional[Tuple[float, float, float, float]] = None,
      prev_page_number: Optional[int] = None,
      x_tolerance: int = DEFAULT_X_TOLERANCE,
      y_tolerance: int = DEFAULT_Y_TOLERANCE,
  ):
    current_table_index = table_index
    current_headers = deepcopy(prev_headers)
    current_headers_raw = deepcopy(prev_headers_raw)
    current_table_bbox = deepcopy(prev_table_bbox)
    current_page_number = page_number
    table_records = []
    res = [
      current_table_index,
      current_headers,
      current_headers_raw,
      current_table_bbox,
      current_page_number,
      table_records
    ]

    # Extract the table content as list of rows (list of lists of cell text)
    raw_table = table_obj.extract(
      x_tolerance=x_tolerance,
      y_tolerance=y_tolerance
    )
    if raw_table is None or len(raw_table) == 0:
      # If extraction yielded no rows, skip this table
      return res

    # Check if this table is a continuation of the previous table
    continuing_table = False
    repeated_header_rows = 0
    if prev_headers is not None and prev_headers_raw is not None:
      # Heuristic 1: If this table is the first on a new page and previous table ended at page bottom
      if prev_page_number is not None and page_number == prev_page_number + 1:
        # Check if previous table likely reached bottom of page (possible continuation)
        # Here we use bbox: if bottom of prev table is near page height, assume continuation
        page_height = page_obj.height
        if prev_table_bbox:
          _, _, _, prev_bottom = prev_table_bbox
          if prev_bottom >= page_height * 0.9:  # within 10% of bottom
            continuing_table = True
        # Also check if first row of current table matches previous header (repeated header)
        first_row_raw = raw_table[0]
        prev_header_first_row_raw = prev_headers_raw[0] if prev_headers_raw else []
        if first_row_raw == prev_header_first_row_raw:
          repeated_header_rows = len(prev_headers_raw)
          continuing_table = True
        # If multi-level header repeated, previous headers might have been multi-row:
        # (We assume if multi-level, entire header repeated similarly)
        # Not fully checking multi-row repeat here for simplicity
      # Heuristic 2: If on the same page and the structure matches previous (possible segmented table)
      if page_number == prev_page_number:
        # If the previous table was on the same page and this table has the same number of columns
        if prev_headers is not None and len(prev_headers) == len(raw_table[0]):
          # If this second table has no clear header row (e.g., its first row is similar to data)
          # we assume it's a continuation (same headers) on the same page.
          continuing_table = True
      # endif page_number == prev_page_number
    # endif prev_headers is not None

    # If this is a continuation, we do not treat it as a new table
    if continuing_table:
      # Use the same table_index as previous and reuse headers
      # These variables remain unchanged:
      # current_table_index = table_index
      # current_headers = prev_headers
      # current_headers_raw = prev_headers_raw
      # If there are repeated header rows in this table extract, remove them
      if repeated_header_rows:
        raw_table = raw_table[repeated_header_rows:]
    else:
      # This is a new table
      current_table_index += 1
      current_headers_raw, raw_table = self.split_header_rows(raw_table)
      current_headers = self.compute_header(current_headers_raw)
      current_page_number = page_number
    # endif continuing_table
    current_table_bbox = table_obj.bbox

    res = [
      current_table_index,
      current_headers,
      current_headers_raw,
      current_table_bbox,
      current_page_number,
      table_records
    ]

    if not raw_table or len(raw_table) == 0:
      return res

    is_nested_structure = self.check_nested_structure(raw_table)
    if is_nested_structure:
      table_records.append({
        "table_index": current_table_index,
        "error": "Table may contain hierarchical/nested rows that cannot be flattened reliably"
      })
      res[5] = table_records
      return res
    # endif nested structure

    # Process each data row into records, merging rows if needed for multi-line cells
    current_record = None
    for row in raw_table:
      # If the first cell has content, it's a start of a new record
      first_cell = row[0]
      if first_cell is not None and first_cell != "":
        # Finalize the previous record if it exists
        if current_record:
          table_records.append(current_record)
        # Start a new record with this row's data
        current_record = {"table_index": current_table_index}
        for col_idx, cell in enumerate(row):
          # Use empty string for None to ensure string values
          value = "" if cell is None else str(cell).strip()
          # Flatten any newline within the cell text
          if "\n" in value:
            value = value.replace("\n", "; ")
          value = self.maybe_convert_numeric(value)
          current_record[current_headers[col_idx]] = value
        # endfor columns
      else:
        # This row is a continuation of the current record (first cell blank or empty)
        if current_record is None:
          # If we find a continuation without a current record, skip (or handle as error)
          continue
        for col_idx, cell in enumerate(row):
          if col_idx >= len(current_headers):
            continue  # skip if row has extra columns unexpectedly
          # Only consider columns where this row has data
          if cell is not None and cell != "":
            new_text = str(cell).strip()
            if "\n" in new_text:
              new_text = new_text.replace("\n", "; ")
            header = current_headers[col_idx]
            # Append to existing text in current record with separator if not empty
            if header in current_record and current_record[header]:
              current_record[header] += "; " + new_text
            else:
              current_record[header] = new_text
          # endif cell has data
        # endfor columns
      # endif continuation or new record
    # After looping through rows, append the last record if exists
    if current_record:
      table_records.append(current_record)

    res[5] = table_records

    return res

  def maybe_detect_missing_horizontal_lines(
      self, page: pdfplumber.page.Page, tables,
      lookahead_px: float = DEFAULT_LOOKAHEAD_PX, epsilon_px: float = 1.0,
      min_gain_px: float = 2.0
  ):
    """
    For each detected table bbox, peek slightly below its bottom for words aligned within its x-span.
    If such words exist (likely the "missing" last row), place a synthetic bottom rule just below them.
    Returns a sorted list of y positions for explicit_horizontal_lines (page-level).
    """
    words = page.extract_words(keep_blank_chars=False) or []
    if not tables or not words:
      return []

    y_candidates = []
    page_h = page.height

    for t in tables:
      if not t.bbox:
        continue
      x0, top, x1, bottom = t.bbox  # pdfplumber coords: smaller y = higher on page
      # Allow a small lookahead below current bbox to catch the unclosed last row
      if lookahead_px == "auto" or lookahead_px is None:
        # Compute median gap between rows and median row height to set lookahead
        rows = [r for r in t.rows if getattr(r, "bbox", None) is not None]
        rows.sort(key=lambda r: r.bbox[1])  # sort by top y
        tops = [r.bbox[1] for r in rows]
        heights = [r.bbox[3] - r.bbox[1] for r in rows]
        gaps = [tops[i] - tops[i - 1] for i in range(1, len(tops))]
        gap_median = float(np.median(gaps)) if len(gaps) > 0 else 0.0
        heights_median = float(np.median(heights))
        lookahead_px = max(
          # only 75% to avoid overshooting into footer of page or next table
          0.75 * max(gap_median,  heights_median),
          DEFAULT_LOOKAHEAD_PX_VALUE
        )
      # endif lookahead_px
      if not isinstance(lookahead_px, float):
        lookahead_px = DEFAULT_LOOKAHEAD_PX_VALUE
      # endif lookahead_px type
      search_bottom = min(page_h, bottom + lookahead_px)

      # Words inside the table corridor (slightly inset to avoid gutters)
      inset = 1.0
      corridor_words = [
        w for w in words
        if (w["x0"] >= x0 + inset and w["x1"] <= x1 - inset
            and w["top"] >= top - inset and w["bottom"] <= search_bottom + inset)
      ]
      if not corridor_words:
        continue

      y_bottom_text = max(w["bottom"] for w in corridor_words)

      # Only add a synthetic line if it is meaningfully below current bbox bottom,
      # i.e., we would actually expand the table downward.
      if y_bottom_text - bottom >= min_gain_px:
        y_explicit = min(page_h - 1.0, y_bottom_text + epsilon_px)
        y_candidates.append(y_explicit)

    # De-duplicate & sort
    y_candidates = sorted({round(y, 2) for y in y_candidates})
    return y_candidates

  def pdf_to_dicts(self, pdf: pdfplumber.PDF):
    """
    Extract tables from a PDF and return a list of dictionaries for each record.

    Each dictionary represents a row of any table, with column names as keys and cell text as values.
    Adds 'table_index' to indicate which table (in order of appearance) the row came from.

    Raises:
        ValueError: If no tables are found in the PDF.
    """
    results = []  # List of output record dictionaries
    table_index = -1  # Will increment when a new table is started
    prev_headers = None  # Store header names of the last processed table
    prev_headers_raw = None  # Store raw header rows of the last processed table
    prev_table_bbox = None  # Store bounding box of last table for multi-page continuity
    prev_page_number = None

    for page_number, page in enumerate(pdf.pages):
      # Use pdfplumber to find tables on the page
      tables = page.find_tables()  # returns Table objects for each detected table
      # Sort tables top-to-bottom by their bounding box (y0 is bottom, y1 is top in pdfplumber coordinates)
      tables.sort(key=lambda t: t.bbox[1] if t.bbox else 0)  # t.bbox = (x0, top, x1, bottom)

      explicit_ys = self.maybe_detect_missing_horizontal_lines(
        page=page,
        tables=tables,
      )

      if explicit_ys:
        tables = page.find_tables(
          table_settings={
            "explicit_horizontal_lines": explicit_ys,
            "intersection_x_tolerance": 8
          }
        )
        tables.sort(key=lambda t: t.bbox[1] if t.bbox else 0)
      # endif explicit_ys

      for t_obj_index, table_obj in enumerate(tables):
        table_index, prev_headers, prev_headers_raw, prev_table_bbox, prev_page_number, table_records = self.__process_table(
          table_obj=table_obj,
          page_obj=page,
          page_number=page_number,
          table_index=table_index,
          prev_headers=prev_headers,
          prev_headers_raw=prev_headers_raw,
          prev_table_bbox=prev_table_bbox,
          prev_page_number=prev_page_number,
        )
        results.extend(table_records)
      # endfor tables
    # endfor pages
    pdf.close()

    # If no tables were output at all, raise an error
    if len(results) == 0:
      raise ValueError("No tables found in the PDF document.")

    return results

  def pdf_path_to_dicts(self, pdf_path: str):
    """
    Extract tables from a PDF and return a list of dictionaries for each record.

    Each dictionary represents a row of any table, with column names as keys and cell text as values.
    Adds 'table_index' to indicate which table (in order of appearance) the row came from.

    Raises:
    FileNotFoundError: If the PDF file is not found or cannot be opened.
    """
    # Try opening the PDF file
    try:
      pdf = pdfplumber.open(pdf_path)
    except Exception as e:
      # If file is missing or unreadable, raise an error with details
      raise FileNotFoundError(f"Cannot open PDF file: {e}")
    return self.pdf_to_dicts(pdf)

  def pdf_base64_to_dicts(self, pdf_base64: str):
    """
    Extract tables from a base64-encoded PDF and return a list of dictionaries for each record.

    Each dictionary represents a row of any table, with column names as keys and cell text as values.
    Adds 'table_index' to indicate which table (in order of appearance) the row came from.

    Raises:
        ValueError: If the base64 string is invalid or cannot be decoded.
    """

    if not isinstance(pdf_base64, (str, bytes)):
      raise TypeError("pdf_b64 must be a str or bytes containing base64-encoded PDF data.")
    # endif type check

    # Normalize to a clean base64 string
    if isinstance(pdf_base64, bytes):
      b64_str = pdf_base64.decode("utf-8", errors="ignore").strip()
    else:
      b64_str = pdf_base64.strip()
    # endif bytes or str

    # Strip data URI prefix if present
    if b64_str.startswith("data:"):
      try:
        b64_str = b64_str.split(",", 1)[1]
      except Exception:
        raise ValueError("Invalid data URI for base64 PDF.")
    # endif data URI

    # Decode base64 -> bytes
    try:
      pdf_bytes = base64.b64decode(b64_str, validate=False)
    except Exception as e:
      raise ValueError(f"Invalid base64 PDF data: {e}")
    # endtry decode

    # Open with pdfplumber from memory
    try:
      pdf = pdfplumber.open(BytesIO(pdf_bytes))
    except Exception as e:
      # Match the style of pdf_to_dicts erroring on open
      raise FileNotFoundError(f"Cannot open PDF from base64: {e}")
    # endtry open

    return self.pdf_to_dicts(pdf)


if __name__ == "__main__":
  print(f"Running PDFParser test...")
  def pdf_path_to_base64(pdf_path: str) -> str:
    with open(pdf_path, "rb") as f:
      pdf_bytes = f.read()
    return base64.b64encode(pdf_bytes).decode("utf-8")

  print(f"Creating PDFParser instance...")
  parser = PDFParser()
  pdf_path = "sample_tables.pdf"  # Replace with your PDF file path

  pdf_base64 = ""  # Optionally, provide a base64 string of a PDF
  pdf_base64 = pdf_path_to_base64(pdf_path)
  tests = [
    {
      "type": "path",
      "data": pdf_path,
      "method": parser.pdf_path_to_dicts,
    },
    {
      "type": "base64",
      "data": pdf_base64,
      "method": parser.pdf_base64_to_dicts,
    }
  ]
  equal_tests_idxs = [
    [0, 1]
  ]
  for it, test in enumerate(tests):
    print(f"Test {it + 1}/{len(tests)}: type={test['type']}")
    prefix = f"[{it + 1}/{len(tests)}]"
    if not test['data']:
      print(f"{prefix}  Skipping empty {test['type']} test.")
      continue
    try:
      records = test['method'](test['data'])
      test['result'] = records
      print(f"{prefix}  Extracted {len(records)} records from {test['type']} input:")
      for rec in records:
        print(f"{prefix}    {json.dumps(rec, indent=2)}")
    except Exception as e:
      print(f"{prefix}  Error processing test {test['type']} input: {e}")
      test['result'] = None
  # endfor tests

  for group in equal_tests_idxs:
    results = [tests[i].get('result') for i in group if 'result' in tests[i]]
    if len(results) < 2:
      continue
    first_result = results[0]
    all_equal = all(res == first_result for res in results[1:])
    if all_equal:
      print(f"Tests {group} produced identical results.")
    else:
      print(f"Tests {group} produced different results.")
    # endif all_equal
  # endfor equal_tests_groups
