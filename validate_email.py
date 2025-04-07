from logging import getLogger
from ssl import SSLContext
from typing import Optional

from .dns_check import dns_check, DefaultAddressTypes, AddressTypes
from .domainlist_check import domainlist_check
from .email_address import EmailAddress
from .exceptions import *
from .regex_check import regex_check
from .smtp_check import smtp_check
import uuid
import threading

LOGGER = getLogger(name=__name__)

__all__ = ['validate_email', 'validate_email_or_fail']
__doc__ = """\
Verify the given email address by determining the SMTP servers
responsible for the domain and then asking them to deliver an email to
the address. Before the actual message is sent, the process is
interrupted.

PLEASE NOTE: Some email providers only tell the actual delivery failure
AFTER having delivered the body which this module doesn't, while others
simply accept everything and send a bounce notification later. Hence, a
100% proper response is not guaranteed.
"""


def validate_email_or_fail(
    email_address: str, *, check_format: bool = True,
    check_blacklist: bool = True, check_dns: bool = True,
    dns_timeout: float = 10, check_smtp: bool = True,
    smtp_timeout: float = 10, smtp_helo_host: Optional[str] = None,
    smtp_from_address: Optional[str] = None,
    smtp_skip_tls: bool = False, smtp_tls_context: Optional[SSLContext] = None,
    smtp_debug: bool = False, address_types: AddressTypes = DefaultAddressTypes
) -> Optional[bool]:
    """
    Return `True` if the email address validation is successful, `None`
    if the validation result is ambiguous, and raise an exception if the
    validation fails.
    """
    email_address_to = EmailAddress(address=email_address)
    
    if check_format:
        regex_check(email_address=email_address_to)
        
    if check_blacklist:
        domainlist_check(email_address=email_address_to)
        
    if not check_dns and not check_smtp:  # check_smtp implies check_dns.
        return True
    
    mx_records = dns_check(
        email_address=email_address_to, timeout=dns_timeout,
        address_types=address_types)
    
    if not check_smtp:
        return True
    
    try:
        email_address_from = None if not smtp_from_address else \
            EmailAddress(address=smtp_from_address)
    except AddressFormatError:
        raise FromAddressFormatError
    return smtp_check(
        email_address=email_address_to, mx_records=mx_records,
        timeout=smtp_timeout, helo_host=smtp_helo_host,
        from_address=email_address_from, skip_tls=smtp_skip_tls,
        tls_context=smtp_tls_context, debug=smtp_debug)


def check_catch_all_domain(domain, mx_records, timeout, from_address=None, test_count=3):
    """Test multiple random emails to reliably detect catch-all domains"""
    accepted_count = 0
    
    for _ in range(test_count):
        random_email = f"{uuid.uuid4()}@{domain}"
        try:
            random_email_to = EmailAddress(random_email)
            smtp_check(
                email_address=random_email_to, mx_records=mx_records,
                timeout=timeout, from_address=from_address
            )
            accepted_count += 1
        except AddressNotDeliverableError:
            # If any address is rejected, not a catch-all
            return False, accepted_count
        except (SMTPCommunicationError, SMTPTemporaryError):
            continue
            
    # Domain accepted all random addresses
    return True, accepted_count

# def validate_email(email_address: str, **kwargs):
#     """
#     Return `True` or `False` depending if the email address exists
#     or/and can be delivered.

#     Return `None` if the result is ambiguous.
#     """
#     try:
#         return validate_email_or_fail(email_address, **kwargs)
#     except SMTPTemporaryError as error:
#         LOGGER.info(
#             msg=f'Validation for {email_address!r} is ambiguous: {error}')
#         return
#     except EmailValidationError as error:
#         LOGGER.info(msg=f'Validation for {email_address!r} failed: {error}')
#         return False

def validate_email(
    email_address: str, *, check_format: bool = True,
    check_blacklist: bool = True, check_dns: bool = True,
    dns_timeout: float = 10, check_smtp: bool = True,
    smtp_timeout: float = 10, smtp_helo_host: Optional[str] = None,
    smtp_from_address: Optional[str] = None,
    smtp_skip_tls: bool = False, smtp_tls_context: Optional[SSLContext] = None,
    smtp_debug: bool = False, address_types: AddressTypes = DefaultAddressTypes
):
    """
    Validates an email address using multiple methods.
    Returns a dictionary with validation results and confidence score.
    """
    
    result = {
        "is_valid": False,
        "code": None,
        "detail": None,
        "confidence": 0,
        "is_catch_all": False,
        "is_role_account": False
    }
    
    # Check for role-based account
    try:
        user_part = email_address.split('@')[0].lower()
        role_prefixes = ['info', 'admin', 'support', 'sales', 'contact', 'hello', 
                         'webmaster', 'postmaster', 'marketing', 'help', 'team', 
                         'billing', 'office', 'mail', 'no-reply', 'noreply']
        result["is_role_account"] = user_part in role_prefixes
    except:
        pass
    
    try:
        email_address_to = EmailAddress(address=email_address)
    except AddressFormatError as error:
        result["code"] = 1
        result["detail"] = str(error)
        result["confidence"] = 0
        return result
    
    if check_format:
        try:
            regex_check(email_address=email_address_to)
        except AddressFormatError as error:
            result["code"] = 1
            result["detail"] = str(error)
            result["confidence"] = 0
            return result
        
    # Start with base confidence for correctly formatted email
    result["confidence"] = 30
    
    if not check_dns:  
        result["code"] = 0
        result["detail"] = 'Valid'
        result["is_valid"] = True
        result["confidence"] = 70  # Higher confidence without full checks
        return result
    
    # Bump confidence for passing format check
    result["confidence"] += 10
    
    if check_blacklist:
        try:
            domainlist_check(email_address=email_address_to)
        except DomainBlacklistedError as error:
            result["code"] = 2
            result["detail"] = str(error)
            result["confidence"] = 5  # Very low confidence for blacklisted domains
            return result
    
    # Bump confidence for passing blacklist check
    result["confidence"] += 10
    
    try:
        mx_records = dns_check(
            email_address=email_address_to, timeout=dns_timeout,
            address_types=address_types)
    except NoValidMXError as error:
        result["code"] = 3
        result["detail"] = str(error)
        result["confidence"] = 20
        return result
    except DomainNotFoundError as error:
        result["code"] = 3
        result["detail"] = str(error)
        result["confidence"] = 5
        return result
    except (NoNameserverError, DNSTimeoutError, DNSConfigurationError, NoMXError) as error:
        result["code"] = 3
        result["detail"] = str(error)
        result["confidence"] = 15
        return result
    
    # Bump confidence for passing DNS check
    result["confidence"] += 15
    
    if not check_smtp:
        result["code"] = 0
        result["detail"] = 'Valid'
        result["is_valid"] = True
        return result
    
    try:
        email_address_from = None if not smtp_from_address else \
            EmailAddress(address=smtp_from_address)
    except AddressFormatError:
        result["code"] = 4
        result["detail"] = str(FromAddressFormatError())
        return result
    
    # Improved catch-all detection with multiple tests
    try:
        # Test multiple random addresses to better detect catch-all
        is_catch_all = True
        for _ in range(2):  # Try 2 different random addresses
            random_email = str(uuid.uuid4())+"@"+ email_address_to.domain
            random_email_to = EmailAddress(random_email)
            try:
                smtp_check(
                    email_address=random_email_to, mx_records=mx_records,
                    timeout=smtp_timeout, helo_host=smtp_helo_host,
                    from_address=email_address_from, skip_tls=smtp_skip_tls,
                    tls_context=smtp_tls_context, debug=smtp_debug)
            except AddressNotDeliverableError:
                # If any random address is rejected, it's not a catch-all domain
                is_catch_all = False
                break
            except (SMTPCommunicationError, SMTPTemporaryError):
                # Communication issues - can't determine
                continue
        
        if is_catch_all:
            result["code"] = 6
            result["detail"] = "Accept all"
            result["is_catch_all"] = True
            result["is_valid"] = True
            # Lower confidence for catch-all domains
            result["confidence"] = max(result["confidence"] - 25, 25)
            return result
            
    except Exception as error:
        # If catch-all detection fails, continue with normal validation
        pass
    
    # Normal SMTP validation for the actual address
    try:
        smtp_check(
            email_address=email_address_to, mx_records=mx_records,
            timeout=smtp_timeout, helo_host=smtp_helo_host,
            from_address=email_address_from, skip_tls=smtp_skip_tls,
            tls_context=smtp_tls_context, debug=smtp_debug)
        result["code"] = 0
        result["detail"] = 'Valid'
        result["is_valid"] = True
        
        # Adjust confidence based on role account
        if result["is_role_account"]:
            result["confidence"] = max(result["confidence"] - 15, 40)
        else:
            result["confidence"] += 15
            
        return result
        
    except AddressNotDeliverableError:
        result["code"] = 5
        result["detail"] = 'Address not deliverable'
        result["confidence"] = 5
        return result
    except SMTPCommunicationError:
        result["code"] = 5
        result["detail"] = 'SMTP communication error'
        result["confidence"] = 20  # Could still be valid but having issues
        return result
    except SMTPTemporaryError:
        result["code"] = 5
        result["detail"] = 'SMTP temporary error'
        result["confidence"] = 30  # Could be valid but server is busy
        return result
    except Exception as error:
        result["code"] = 5
        result["detail"] = f'SMTP error: {str(error)}'
        result["confidence"] = 15
        return result