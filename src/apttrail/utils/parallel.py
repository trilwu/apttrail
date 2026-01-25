"""
Parallel processing utilities for APTtrail.

Provides thread-safe parallel processing for file operations.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class ParallelProcessor:
    """
    Thread-safe parallel processor for file operations.

    Attributes:
        max_workers: Maximum number of worker threads
    """

    DEFAULT_WORKERS: int = 8

    def __init__(self, max_workers: int = DEFAULT_WORKERS) -> None:
        """
        Initialize the parallel processor.

        Args:
            max_workers: Maximum number of concurrent workers
        """
        self.max_workers = max_workers

    def process_files(
        self,
        files: list[Path],
        processor: Callable[[Path], T],
        show_progress: bool = True,
    ) -> list[tuple[Path, T]]:
        """
        Process multiple files in parallel.

        Args:
            files: List of file paths to process
            processor: Function to apply to each file
            show_progress: Whether to show progress output

        Returns:
            List of (file_path, result) tuples
        """
        results: list[tuple[Path, T]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(processor, f): f for f in files}

            completed = 0
            total = len(files)

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                completed += 1

                try:
                    result = future.result()
                    results.append((file_path, result))

                    if show_progress and completed % 50 == 0:
                        print(f"  Processed {completed}/{total} files...")

                except Exception as e:
                    print(f"Error processing {file_path.name}: {e}")

        return results

    def process_items(
        self,
        items: list[Any],
        processor: Callable[[Any], T],
        show_progress: bool = False,
    ) -> list[T]:
        """
        Process multiple items in parallel.

        Args:
            items: List of items to process
            processor: Function to apply to each item
            show_progress: Whether to show progress output

        Returns:
            List of results
        """
        results: list[T] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {executor.submit(processor, item): item for item in items}

            for future in as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    if show_progress:
                        print(f"Error processing item: {e}")

        return results
