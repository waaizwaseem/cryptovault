"""
CryptoVault — DSA Module
========================
Student part: Linked List, Stack, Queue, Merge Sort, Binary Search, Linear Search.

This module is imported by main.py. It does NOT import cryptofunctions.py —
all crypto callbacks are passed in, keeping the two modules independent.
"""

import datetime
import os


# ══════════════════════════════════════════════════════════════
# 1. LINKED LIST  →  Operation History Log
# ══════════════════════════════════════════════════════════════

class LogNode:
    """
    One node in the history linked list.

    Fields
    ------
    operation_id  : auto-incrementing integer
    action        : what happened  e.g. "ENCRYPT", "DECRYPT", "HASH", "CREATE"
    file_name     : which file was involved
    algorithm     : which cipher/hash was used  e.g. "Caesar", "AES", "SHA-256"
    status        : "SUCCESS" or "FAILED"
    timestamp     : date-time string when the operation ran
    next          : pointer to the next LogNode (None = end of list)
    """

    def __init__(self, operation_id, action, file_name,
                 algorithm="N/A", status="SUCCESS"):
        self.operation_id = operation_id
        self.action       = action
        self.file_name    = file_name
        self.algorithm    = algorithm
        self.status       = status
        self.timestamp    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.next         = None


class LinkedList:
    """Singly linked list — stores every CryptoVault operation as a log entry."""

    def __init__(self):
        self.head   = None
        self._count = 0

    # ── core operations ────────────────────────────────────────

    def append(self, action, file_name, algorithm="N/A", status="SUCCESS"):
        """Append a new log entry at the tail of the list. O(n)."""
        self._count += 1
        new_node = LogNode(self._count, action, file_name, algorithm, status)

        if self.head is None:
            self.head = new_node
            return new_node

        current = self.head
        while current.next:
            current = current.next
        current.next = new_node
        return new_node

    def to_list(self):
        """Return all nodes as a plain Python list (used by sort and search)."""
        records, current = [], self.head
        while current:
            records.append(current)
            current = current.next
        return records

    def count(self):
        return self._count

    # ── display helpers ────────────────────────────────────────

    def display(self, limit=None):
        """Print log entries. Pass limit=N to show only the last N entries."""
        records = self.to_list()
        if not records:
            print("\n  [Activity Log] No operations recorded yet.")
            return

        if limit:
            records = records[-limit:]

        print(f"\n  {'ID':<5} {'Action':<12} {'Algorithm':<18} "
              f"{'Status':<10} {'File':<25} Timestamp")
        print("  " + "─" * 85)
        for r in records:
            print(f"  {r.operation_id:<5} {r.action:<12} {r.algorithm:<18} "
                  f"{r.status:<10} {r.file_name:<25} {r.timestamp}")

    def save_to_file(self, output_path):
        """Write the full log to a plain-text file."""
        records = self.to_list()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"{'ID':<5} {'Action':<12} {'Algorithm':<18} "
                    f"{'Status':<10} {'File':<25} Timestamp\n")
            f.write("─" * 85 + "\n")
            for r in records:
                f.write(f"{r.operation_id:<5} {r.action:<12} {r.algorithm:<18} "
                        f"{r.status:<10} {r.file_name:<25} {r.timestamp}\n")
        return output_path


# ══════════════════════════════════════════════════════════════
# 2. STACK  →  Undo Last Operation
# ══════════════════════════════════════════════════════════════

class UndoStack:
    """
    LIFO stack — every successful file operation pushes a record here
    so the user can reverse it with Undo.

    Each entry is a dict:
        { "action", "file_name", "output_path", "algorithm", "extra" }
    """

    def __init__(self):
        self._data = []

    def push(self, action, file_name, output_path="", algorithm="N/A", extra=""):
        """Push an undo record. Called immediately after a successful operation."""
        entry = {
            "action":      action,
            "file_name":   file_name,
            "output_path": output_path,
            "algorithm":   algorithm,
            "extra":       extra,
        }
        self._data.append(entry)

    def pop(self):
        """
        Pop and return the most recent record.
        Returns None if the stack is empty.
        """
        if self.is_empty():
            return None
        return self._data.pop()

    def peek(self):
        """Return the top record without removing it."""
        return self._data[-1] if self._data else None

    def is_empty(self):
        return len(self._data) == 0

    def size(self):
        return len(self._data)


# ══════════════════════════════════════════════════════════════
# 3. QUEUE  →  Batch File Processing  (FIFO)
# ══════════════════════════════════════════════════════════════

class BatchQueue:
    """
    FIFO queue for batch crypto jobs.
    Jobs are added at the back and processed from the front.

    Each job is a dict:
        { "file_name", "operation" }
    where operation is one of:
        "CAESAR" | "TRANSPOSITION" | "AES" | "SHA256"
    """

    def __init__(self):
        self._data = []

    def enqueue(self, file_name, operation):
        """Add a job to the back of the queue."""
        self._data.append({"file_name": file_name, "operation": operation})

    def dequeue(self):
        """Remove and return the front job. Returns None if empty."""
        if self.is_empty():
            return None
        return self._data.pop(0)

    def remove_front(self):
        """Alias for dequeue — used by the 'Remove next file' menu option."""
        return self.dequeue()

    def clear(self):
        self._data.clear()

    def display(self):
        """Print all pending jobs without removing them."""
        if self.is_empty():
            print("\n  [Batch Queue] No pending jobs.")
            return
        print(f"\n  Pending batch jobs ({len(self._data)} total):")
        print(f"  {'#':<5} {'Operation':<18} File")
        print("  " + "─" * 50)
        for i, job in enumerate(self._data, 1):
            print(f"  {i:<5} {job['operation']:<18} {job['file_name']}")

    def process_all(self, crypto_callback):
        """
        Drain the queue, calling crypto_callback(job) on each item.
        crypto_callback receives the job dict and handles the actual encryption.
        Returns a list of result dicts from each callback.
        """
        results = []
        total = len(self._data)
        print(f"\n  [Batch] Starting — {total} job(s) queued.")
        while not self.is_empty():
            job = self.dequeue()
            result = crypto_callback(job)
            results.append(result)
        print("  [Batch] All jobs complete.\n")
        return results

    def is_empty(self):
        return len(self._data) == 0

    def size(self):
        return len(self._data)


# ══════════════════════════════════════════════════════════════
# 4. MERGE SORT  →  Sort log records
# ══════════════════════════════════════════════════════════════

def merge_sort(records, key="file_name"):
    """
    Recursive merge sort on a list of LogNode objects.

    key: "file_name" | "timestamp" | "action" | "algorithm" | "operation_id"
    Returns a NEW sorted list — does not modify the original.
    Time complexity: O(n log n) in all cases.
    """
    if len(records) <= 1:
        return records

    mid   = len(records) // 2
    left  = merge_sort(records[:mid],  key)
    right = merge_sort(records[mid:], key)
    return _merge(left, right, key)


def _merge(left, right, key):
    """Merge two sorted halves into one sorted list."""
    result, i, j = [], 0, 0

    while i < len(left) and j < len(right):
        val_l = getattr(left[i],  key)
        val_r = getattr(right[j], key)
        # Compare numerically for operation_id, alphabetically for strings
        if val_l <= val_r:
            result.append(left[i]);  i += 1
        else:
            result.append(right[j]); j += 1

    result.extend(left[i:])
    result.extend(right[j:])
    return result


# ══════════════════════════════════════════════════════════════
# 5. SEARCH  →  Binary Search + Linear Search
# ══════════════════════════════════════════════════════════════

def binary_search_by_file(sorted_records, target_name):
    """
    Binary search on records sorted by file_name (exact match).
    Returns the FIRST matching LogNode, or None.
    Pre-condition: list must be sorted by file_name.
    Time complexity: O(log n).
    """
    low, high = 0, len(sorted_records) - 1

    while low <= high:
        mid  = (low + high) // 2
        name = sorted_records[mid].file_name

        if name == target_name:
            return sorted_records[mid]
        elif name < target_name:
            low  = mid + 1
        else:
            high = mid - 1

    return None


def binary_search_by_id(sorted_records, target_id):
    """
    Binary search on records sorted by operation_id (exact match).
    Returns the matching LogNode, or None.
    Time complexity: O(log n).
    """
    low, high = 0, len(sorted_records) - 1

    while low <= high:
        mid = (low + high) // 2
        oid = sorted_records[mid].operation_id

        if oid == target_id:
            return sorted_records[mid]
        elif oid < target_id:
            low  = mid + 1
        else:
            high = mid - 1

    return None


def linear_search(records, query, field="file_name"):
    """
    Linear search — case-insensitive partial match on any field.

    field: "file_name" | "action" | "algorithm" | "status"
    Returns a list of all matching LogNode objects.
    Time complexity: O(n).
    """
    query = query.lower()
    return [
        r for r in records
        if query in str(getattr(r, field, "")).lower()
    ]
