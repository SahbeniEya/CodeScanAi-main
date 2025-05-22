"""
This module provides util methods for extracting code summaries from a list of files.
"""

import logging
import os

# Only set up logging if it hasn't been configured already
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.WARNING, format="%(asctime)s - %(name)-25s %(levelname)-8s %(message)s"
    )

# Create a logger specific to this module
logger = logging.getLogger("code_summary_extractor")
logger.setLevel(logging.ERROR)  # Set to ERROR to reduce noise from permission errors


def read_files_and_extract_code_summary(file_paths):
    """
    Reads the content of the given files and generates a code summary.
    Skips files that cannot be decoded as text.

    Parameters:
        file_path (list[string]): The list of filenames to extract code from.

    Returns:
        string: summary of code extracted from the input files.
    """
    code_summary = ""
    # Skip binary file extensions and system directories
    binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.obj', '.o', '.a', '.lib',
                         '.bin', '.dat', '.db', '.sqlite', '.jpg', '.jpeg', '.png',
                         '.gif', '.bmp', '.tiff', '.ico', '.mp3', '.mp4', '.avi',
                         '.mov', '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar']

    skip_dirs = ['node_modules', 'venv', '.git', '.svn', '.hg', '__pycache__',
                 'build', 'dist', 'Arduino15', 'packages', 'D3DSCache']

    for file_path in file_paths:
        # Skip files in directories we want to ignore
        if any(skip_dir in file_path for skip_dir in skip_dirs):
            continue

        # Skip binary files by extension
        if os.path.splitext(file_path)[1].lower() in binary_extensions:
            continue

        if os.path.isfile(file_path):
            # Skip files that are likely to cause permission errors
            if '.lock' in file_path or '.val' in file_path or '.idx' in file_path:
                logger.debug("Skipping potential system file: %s", file_path)
                continue

            try:
                # First try UTF-8
                with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                    logger.debug("Reading: %s", file_path)  # Changed to debug level to reduce noise
                    code_summary += f"\n\nFile: {os.path.basename(file_path)}\n"
                    code_summary += file.read()
            except (UnicodeDecodeError, IOError, PermissionError) as e:
                try:
                    # If UTF-8 fails, try with Latin-1 which can read any byte
                    with open(file_path, "r", encoding="latin-1") as file:
                        code_summary += f"\n\nFile: {os.path.basename(file_path)}\n"
                        code_summary += file.read()
                except (IOError, PermissionError) as e:
                    # Log at debug level for permission errors to reduce noise
                    if isinstance(e, PermissionError):
                        logger.debug("Skipping file due to permissions: %s", file_path)
                    else:
                        logger.warning("Skipping file %s: %s", file_path, e)
        else:
            logger.debug("Skipped %s: Not a valid file.", file_path)  # Changed to debug level
    return code_summary


def generate_code_summary(directory, changed_files):
    """
    Generates a summary of the code from the changed files.

    Parameters:
        directory (string) : The path to the directory.
        changed_files (list[string]): The list of filenames to extract code from.

    Returns:
        string: summary of code extracted from the input files.
    """
    file_paths = [os.path.join(directory, file) for file in changed_files]
    return read_files_and_extract_code_summary(file_paths)
