"""
Progress tracking utility for GrepIntel.

This module provides functionality to track and display progress of long-running operations.
"""

import sys
import time
from typing import Optional


class ProgressTracker:
    """
    Progress tracker class

    Tracks progress of operations and displays progress information to the user.
    """

    def __init__(self, total_items: int, description: str = "Processing"):
        """
        Constructor

        Args:
            total_items: Total number of items to process
            description: Description of the operation
        """
        self.total_items = total_items
        self.processed_items = 0
        self.description = description
        self.start_time = time.time()

        # Initialize progress display
        self._print_progress()

    def update(self, items_processed: int = 1) -> None:
        """
        Update progress

        Args:
            items_processed: Number of items processed in this update
        """
        self.processed_items += items_processed
        self._print_progress()

    def _print_progress(self) -> None:
        """Print current progress information"""
        if self.total_items == 0:
            percentage = 100
        else:
            percentage = min(100, int((self.processed_items / self.total_items) * 100))

        elapsed_time = time.time() - self.start_time

        # Calculate estimated time remaining
        if self.processed_items > 0:
            items_per_second = self.processed_items / elapsed_time
            remaining_items = self.total_items - self.processed_items
            estimated_remaining_time = (
                remaining_items / items_per_second if items_per_second > 0 else 0
            )
        else:
            estimated_remaining_time = 0

        # Create progress bar
        bar_length = 30
        filled_length = int(bar_length * percentage / 100)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        # Format progress string
        progress_str = f"\r{self.description}: [{bar}] {percentage}% ({self.processed_items}/{self.total_items})"

        # Add time information
        if self.processed_items > 0 and estimated_remaining_time > 1:
            progress_str += f" | Estimated time remaining: {self._format_time(estimated_remaining_time)}"

        # Print progress
        sys.stdout.write(progress_str)
        sys.stdout.flush()

        # Print newline when complete
        if self.processed_items >= self.total_items:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def _format_time(self, seconds: float) -> str:
        """
        Format time in seconds to a human-readable string

        Args:
            seconds: Time in seconds

        Returns:
            str: Formatted time string
        """
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            seconds = seconds % 60
            return f"{minutes} minutes {seconds:.0f} seconds"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours} hours {minutes} minutes"
