# ===================
# author: Peter Lacko
# year: 2016
# ===================

"""Set of custom exceptions."""


class UserExistsException(Exception):
    """User with given name or phone number already exists."""
    pass


class InvitationExistsException(Exception):
    """Invitation for given user has already been created."""
    pass


class UnexceptedException(Exception):
    """Unexcepted exception."""
    pass
