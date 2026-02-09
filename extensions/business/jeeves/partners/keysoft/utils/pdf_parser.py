import traceback
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

USE_HEADER_TEMPLATE_FALLBACK = False


class PDFParser:
  def __init__(self):
    return

  def split_header_rows(
      self,
      raw_table: List[List[str]],
  ):
    """
    Split a raw table into header rows and data rows.

    Parameters
    ----------
    raw_table : list[list[str]]
      Table rows as returned by `pdfplumber.Table.extract`.

    Returns
    -------
    tuple[list[list[str]], list[list[str]]]
      Header rows (may be empty) and the remaining data rows.
    """
    header_rows = []
    # Identify header rows: continue until a row with no None (or until data likely starts)
    for row_idx, row in enumerate(raw_table):
      is_row_full = all(cell is not None and str(cell).strip() != "" for cell in row)
      # If we have no header rows yet and the first row is already "full",
      # treat the table as headerless and keep all rows as data.
      if not header_rows and is_row_full:
        return [], raw_table[row_idx:]
      if is_row_full:
        # First complete row after header scaffold marks the start of data.
        raw_data_rows = raw_table[row_idx:]
        return header_rows, raw_data_rows
      header_rows.append(row)
      # endif row eligible for header
    # endfor rows
    raw_data_rows = raw_table[len(header_rows):]
    return header_rows, raw_data_rows

  def _recover_header_words(
      self,
      header_rows: List[List[str]],
      table_obj: pdfplumber.table.Table,
      page_obj: pdfplumber.page.Page,
  ) -> List[List[str]]:
    """
    Fill blank header cells by re-reading words from the PDF within the cell bbox.

    Parameters
    ----------
    header_rows : list[list[str]]
      Current header rows extracted from the table.
    table_obj : pdfplumber.table.Table
      Table object containing bbox metadata.
    page_obj : pdfplumber.page.Page
      Page object to extract words from.

    Returns
    -------
    list[list[str]]
      Header rows with blanks filled when possible.
    """
    words = page_obj.extract_words(keep_blank_chars=False) or []
    columns = list(getattr(table_obj, "columns", []))
    rows = list(getattr(table_obj, "rows", []))
    if not words or not columns or not rows:
      return header_rows

    def _overlap(a0, a1, b0, b1):
      return max(0.0, min(a1, b1) - max(a0, b0))

    header_count = min(len(header_rows), len(rows))
    enriched = [list(r) for r in header_rows]

    # Tighten row bands to reduce overlap: cap each row (except last) at the next row's top.
    row_spans = []
    for i in range(header_count):
      r_bbox = getattr(rows[i], "bbox", None)
      if r_bbox is None:
        row_spans.append(None)
        continue
      rx0, rtop, rx1, rbottom = r_bbox
      if i < header_count - 1:
        next_bbox = getattr(rows[i + 1], "bbox", None)
        if next_bbox:
          rbottom = min(rbottom, next_bbox[1] - 0.5)
      row_spans.append((rx0, rtop, rx1, rbottom))

    for r_idx in range(header_count):
      row_bbox = row_spans[r_idx]
      if row_bbox is None:
        continue
      rx0, rtop, rx1, rbottom = row_bbox
      for c_idx in range(min(len(columns), len(enriched[r_idx]))):
        current_val = enriched[r_idx][c_idx]
        if current_val is not None and str(current_val).strip() != "":
          continue
        col_bbox = getattr(columns[c_idx], "bbox", None)
        if col_bbox is None:
          continue
        cx0, ctop, cx1, cbottom = col_bbox
        cell_bbox = (cx0, rtop, cx1, rbottom)

        cell_words = [
          w for w in words
          if _overlap(w["x0"], w["x1"], cell_bbox[0], cell_bbox[2]) > 0
          and _overlap(w["top"], w["bottom"], cell_bbox[1], cell_bbox[3]) > 0
        ]
        if not cell_words:
          continue
        cell_words.sort(key=lambda w: (w["x0"], w["top"]))
        text = " ".join(w["text"] for w in cell_words).strip()
        if text:
          enriched[r_idx][c_idx] = text

    return enriched


  def compute_header(
      self,
      header_rows: List[List[str]],
      table_obj: Optional[pdfplumber.table.Table] = None,
      page_obj: Optional[pdfplumber.page.Page] = None,
      use_header_template_fallback: bool = USE_HEADER_TEMPLATE_FALLBACK,
  ):
    """
    Build normalized column names from header rows.

    Parameters
    ----------
    header_rows : list[list[str]]
      Rows identified as header content.
    table_obj : pdfplumber.table.Table, optional
      Source table (used to recover header text from bboxes when cells are blank).
    page_obj : pdfplumber.page.Page, optional
      Page object (used alongside `table_obj` to look up words).
    use_header_template_fallback : bool, optional
      Whether to apply the header template fallback logic for common patterns.

    Returns
    -------
    list[str]
      Normalized, unique column names.
    """
    if not header_rows:
      return []
    def _is_blank(cell) -> bool:
      return cell is None or str(cell).strip() == ""

    # Try to recover missing header text directly from the PDF using word bboxes.
    if table_obj is not None and page_obj is not None:
      header_rows = self._recover_header_words(
        header_rows=header_rows,
        table_obj=table_obj,
        page_obj=page_obj,
      )

    # Optional template fallback: fill missing group labels in the classic balance-sheet pattern.
    if use_header_template_fallback and len(header_rows) >= 2:
      first_row = header_rows[0]
      second_row = header_rows[1]
      # Remove the first two columns which often contain row labels and are not part
      # of the repeating group pattern(e.g., account names), then check if the rest
      # of the first 2 rows follows a debit/credit pattern.
      tail_first = first_row[2:] if len(first_row) > 2 else []
      tail_second = second_row[2:] if len(second_row) > 2 else []
      non_empty_tail_first = [c for c in tail_first if not _is_blank(c)]
      second_tokens = [str(c).strip().lower() if not _is_blank(c) else "" for c in tail_second]
      # If group labels are blank but we see debit/credit pairs, inject known labels.
      # This is scoped to the classic balance-sheet layout so non-blank headers stay untouched.
      has_deb_cred_pattern = (
        len(tail_second) >= 2 and len(tail_second) % 2 == 0 and
        all(tok in {"debitoare", "creditoare", ""} for tok in second_tokens)
      )
      if not non_empty_tail_first and has_deb_cred_pattern:
        num_pairs = len(tail_second) // 2
        base_labels = [
          "Solduri initiale an",
          "Rulaje Perioada",
          "Total Rulaje",
          "Sume totale",
          "Solduri finale",
        ]
        if num_pairs > len(base_labels):
          extra = [f"Group{i + 1}" for i in range(num_pairs - len(base_labels))]
          base_labels.extend(extra)
        first_row_filled = list(first_row)
        if len(first_row_filled) < 2:
          first_row_filled.extend([""] * (2 - len(first_row_filled)))
        for i in range(num_pairs):
          label = base_labels[i]
          # each group occupies two columns
          col_idx = 2 + i * 2
          # expand row if necessary
          while len(first_row_filled) <= col_idx:
            first_row_filled.append("")
          first_row_filled[col_idx] = label
          if len(first_row_filled) <= col_idx + 1:
            first_row_filled.append("")
          first_row_filled[col_idx + 1] = label
        header_rows = [first_row_filled] + header_rows[1:]
      # endif
    # endif template fallback logic

    # Propagate labels horizontally within each header row when cells are blank.
    propagated_rows = []
    for row in header_rows:
      new_row = []
      last_val = ""
      for col_idx, cell in enumerate(row):
        if _is_blank(cell):
          # only propagate within header blocks beyond the first two columns
          if col_idx >= 2 and last_val:
            new_row.append(last_val)
          else:
            new_row.append("")
        else:
          text = str(cell).strip().replace("\n", " ")
          # If the current token is a substring of the previous non-empty header,
          # prefer the fuller previous header to keep group labels aligned.
          if last_val and text in last_val and len(text) < len(last_val):
            text = last_val
          new_row.append(text)
          last_val = text
      propagated_rows.append(new_row)
    header_rows = propagated_rows

    filled_header = []
    for row in header_rows:
      filled_row = []
      for cell in row:
        stripped_cell = str(cell).strip().replace('\n', ' ') if cell is not None else ""
        filled_row.append(stripped_cell)
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
            text = hr[col_idx]
            if not parts or text.lower() != parts[-1].lower():
              parts.append(text)
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

  def _table_score(
      self,
      table_obj: pdfplumber.table.Table,
      x_tolerance: int = DEFAULT_X_TOLERANCE,
      y_tolerance: int = DEFAULT_Y_TOLERANCE,
  ):
    """
    Compute a simple quality score for a detected table.

    Parameters
    ----------
    table_obj : pdfplumber.table.Table
      Table object to score.
    x_tolerance : int, optional
      Horizontal tolerance used when extracting the table.
    y_tolerance : int, optional
      Vertical tolerance used when extracting the table.

    Returns
    -------
    tuple[int, int]
      (data_row_count, header_character_count). Higher is better.
    """
    try:
      raw_table = table_obj.extract(
        x_tolerance=x_tolerance,
        y_tolerance=y_tolerance
      )
    except Exception:
      return (0, 0)
    if not raw_table:
      return (0, 0)
    header_rows, _ = self.split_header_rows(raw_table)
    data_rows = raw_table[len(header_rows):]
    header_chars = sum(
      len(str(c).strip())
      for row in header_rows
      for c in row
      if c is not None and str(c).strip() != ""
    )
    return (len(data_rows), header_chars)

  def total_score(
      self,
      tables_list: list[pdfplumber.table.Table],
      x_tolerance: int = DEFAULT_X_TOLERANCE,
      y_tolerance: int = DEFAULT_Y_TOLERANCE,
  ):
    """
    Aggregate score across multiple tables.

    Parameters
    ----------
    tables_list : list of pdfplumber.table.Table
      Tables to evaluate.
    x_tolerance : int, optional
      Horizontal tolerance used when extracting the table.
    y_tolerance : int, optional
      Vertical tolerance used when extracting the table.

    Returns
    -------
    tuple[int, int]
      Sum of per-table data rows and header characters.
    """
    scores = [self._table_score(tb, x_tolerance=x_tolerance, y_tolerance=y_tolerance) for tb in tables_list]
    return (sum(s[0] for s in scores), sum(s[1] for s in scores))

  def check_nested_structure(self, raw_table: List[List[str]]) -> bool:
    """
    Detect likely hierarchical/nested rows (multiple leading empty cells).
    Ignores one trailing summary-like row (structural, not lexical) and
    strips trailing fully blank rows to reduce false positives.

    Parameters
    ----------
    raw_table : list[list[str]]
      Extracted table rows.

    Returns
    -------
    bool
      True if the table appears hierarchical and should be skipped.

    Notes
    -----
    Flags rows with multiple leading blanks while ignoring a trailing
    structural summary row and trailing blank rows to reduce false positives.
    """

    def _is_blank_row(row):
      return all(c is None or str(c).strip() == "" for c in row)

    def _is_structural_summary_row(row: List[str]) -> bool:
      # Token-agnostic: (1) many leading blanks, (2) numeric-heavy on right-half
      if not row:
        return False
      n = len(row)

      # leading blanks
      i = 0
      while i < n and (row[i] is None or str(row[i]).strip() == ""):
        i += 1
      leading_blanks = i

      # numeric flags
      def _numish(s):
        v = self.maybe_convert_numeric(s)
        return isinstance(v, (int, float))

      right_half = row[n // 2:] if n >= 2 else row
      numeric_right = sum(1 for c in right_half if _numish(c))
      numeric_total = sum(1 for c in row if _numish(c))
      non_empty = sum(1 for c in row if c is not None and str(c).strip() != "")

      # thresholds: at least one leading blank, ≥60% of right-half numeric,
      # and overall numeric density reasonably high, but row not “full” of text
      right_ratio = (numeric_right / max(1, len(right_half)))
      total_ratio = (numeric_total / max(1, n))

      return (leading_blanks >= 1) and (right_ratio >= 0.6) and (total_ratio >= 0.5) and (non_empty <= int(0.75 * n))

    rows = list(raw_table)

    # Trim trailing fully blank rows
    while rows and _is_blank_row(rows[-1]):
      rows.pop()

    # Ignore a *single* trailing structural summary row
    if rows and _is_structural_summary_row(rows[-1]):
      rows = rows[:-1]

    # Count rows with >1 leading blanks (true hierarchy) among the rest
    offences = 0
    for r in rows:
      blanks = 0
      for c in r:
        if c is None or str(c).strip() == "":
          blanks += 1
        else:
          break
      if blanks > 1:
        offences += 1

    return offences >= 2

  def maybe_convert_numeric(self, s):
    """
    Attempt to coerce a cell value to an int or float.

    Parameters
    ----------
    s : Any
      Cell value.

    Returns
    -------
    int or float or Any
      Parsed numeric value when possible; otherwise the original input.
    """
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
      use_header_template_fallback: bool = USE_HEADER_TEMPLATE_FALLBACK,
  ):
    """
    Process a single table and return updated parser state plus records.

    Parameters
    ----------
    table_obj : pdfplumber.table.Table
      Table to process.
    page_obj : pdfplumber.page.Page
      Page containing the table.
    page_number : int
      Zero-based page index.
    table_index : int, optional
      Current table index accumulator.
    prev_headers : list[str], optional
      Headers from the previous table (for continuation detection).
    prev_headers_raw : list[list[str]], optional
      Raw header rows from the previous table.
    prev_table_bbox : tuple[float, float, float, float], optional
      Bounding box of the previous table.
    prev_page_number : int, optional
      Page number of the previous table.
    x_tolerance : int, optional
      Extraction horizontal tolerance.
    y_tolerance : int, optional
      Extraction vertical tolerance.
    use_header_template_fallback : bool, optional
      Whether to apply the header template fallback logic.

    Returns
    -------
    list
      Updated (table_index, headers, headers_raw, bbox, page_number, records).
    """
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
      current_headers = self.compute_header(
        current_headers_raw, use_header_template_fallback=use_header_template_fallback
      )
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

    while raw_table and all((c is None or str(c).strip() == "") for c in raw_table[-1]):
      raw_table.pop()

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

    Parameters
    ----------
    page : pdfplumber.page.Page
      Page containing the tables.
    tables : list
      Tables detected on the page.
    lookahead_px : float, optional
      Pixels to search below the table bottom (auto by default).
    epsilon_px : float, optional
      Offset to place the synthetic line below detected text.
    min_gain_px : float, optional
      Minimum extension below the existing bbox to consider a line.

    Returns
    -------
    list[float]
      Sorted y-positions for `explicit_horizontal_lines`.
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

  def pdf_to_dicts(self, pdf: pdfplumber.PDF, use_header_template_fallback: bool = USE_HEADER_TEMPLATE_FALLBACK):
    """
    Extract tables from a PDF and return a list of dictionaries for each record.

    Each dictionary represents a row of any table, with column names as keys and cell text as values.
    Adds 'table_index' to indicate which table (in order of appearance) the row came from.

    Parameters
    ----------
    pdf : pdfplumber.PDF
      Open pdfplumber document.
    use_header_template_fallback : bool, optional
      Whether to apply the header template fallback logic for common patterns.

    Returns
    -------
    list[dict]
      One dict per extracted row, including `table_index`.

    Raises
    ------
    ValueError
      If no tables are found in the PDF.
    """
    results = []  # List of output record dictionaries
    table_index = -1  # Will increment when a new table is started
    prev_headers = None  # Store header names of the last processed table
    prev_headers_raw = None  # Store raw header rows of the last processed table
    prev_table_bbox = None  # Store bounding box of last table for multi-page continuity
    prev_page_number = None

    for page_number, page in enumerate(pdf.pages):
      # Use pdfplumber to find tables on the page
      tables_base = page.find_tables()  # returns Table objects for each detected table
      # Sort tables top-to-bottom by their bounding box (y0 is bottom, y1 is top in pdfplumber coordinates)
      tables_base.sort(key=lambda t: t.bbox[1] if t.bbox else 0)  # t.bbox = (x0, top, x1, bottom)
      tables = list(tables_base)

      explicit_ys = self.maybe_detect_missing_horizontal_lines(
        page=page,
        tables=tables_base,
      )

      if explicit_ys:
        tables_with_lines = page.find_tables(
          table_settings={
            "explicit_horizontal_lines": explicit_ys,
            "intersection_x_tolerance": 8
          }
        )
        tables_with_lines.sort(key=lambda t: t.bbox[1] if t.bbox else 0)
        if self.total_score(tables_with_lines) > self.total_score(tables):
          tables = tables_with_lines
        # endif better score with explicit lines
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
          use_header_template_fallback=use_header_template_fallback,
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

  def pdf_base64_to_dicts(self, pdf_base64: str, use_header_template_fallback: bool = USE_HEADER_TEMPLATE_FALLBACK):
    """
    Extract tables from a base64-encoded PDF and return a list of dictionaries for each record.

    Each dictionary represents a row of any table, with column names as keys and cell text as values.
    Adds 'table_index' to indicate which table (in order of appearance) the row came from.

    Parameters
    ----------
    pdf_base64 : str
      Base64 string (optionally prefixed with a data URI) representing a PDF.
    use_header_template_fallback : bool, optional
      Whether to apply the header template fallback logic for common patterns.

    Returns
    -------
    list[dict]
      One dict per extracted row, including `table_index`.

    Raises
    ------
    TypeError
      If the input is not str or bytes.
    ValueError
      If base64 decoding fails.
    FileNotFoundError
      If the decoded PDF cannot be opened.
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

    return self.pdf_to_dicts(pdf, use_header_template_fallback=use_header_template_fallback)


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
      print(f"{prefix}  Error processing test {test['type']} input: {e}\n{traceback.format_exc()}")
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
