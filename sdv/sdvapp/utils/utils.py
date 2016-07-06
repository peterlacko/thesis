# ===================
# author: peter lacko
# year: 2016
# ===================

# Module provides some utility functions

from uuid import uuid4


def get_file_path(instance, filename):
    """Helper function to get random path for file."""
    return str(uuid4())
