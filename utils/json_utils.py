import json
import logging
import re

def escape_control_characters(s):
    """
    Escape unescaped control characters in a string.
    Converts literal newlines, carriage returns, and tabs to their escaped versions.
    """
    if not isinstance(s, str):
        return s
    
    # We need to be careful to only escape unescaped control characters
    # This is tricky because we're working with raw strings
    
    # Replace actual control characters with escaped versions
    # But be careful not to double-escape already escaped sequences
    result = []
    i = 0
    while i < len(s):
        char = s[i]
        
        # Check for already escaped sequences
        if char == '\\' and i + 1 < len(s):
            next_char = s[i + 1]
            # If it's already an escape sequence, keep it as is
            if next_char in 'nrtu"\\/:bfv':
                result.append(char)
                result.append(next_char)
                i += 2
                continue
        
        # Replace actual control characters
        if char == '\n':
            result.append('\\n')
        elif char == '\r':
            result.append('\\r')
        elif char == '\t':
            result.append('\\t')
        elif ord(char) < 32:  # Other control characters
            result.append(f'\\u{ord(char):04x}')
        else:
            result.append(char)
        
        i += 1
    
    return ''.join(result)


def parse_json_with_escaping(json_string):
    """
    Parse JSON with automatic escaping of control characters.
    First attempts direct parsing, then tries with escaping if that fails.
    """
    try:
        # First attempt: direct parsing
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        try:
            # Second attempt: escape control characters and try again
            escaped_json = escape_control_characters(json_string)
            return json.loads(escaped_json)
        except json.JSONDecodeError as e2:
            logging.error(f"Failed to parse JSON even after escaping: {str(e2)}")
            logging.error(f"Original error: {str(e)}")
            raise e2


def safe_json_loads(text, fallback=None):
    """
    Safely load JSON with error handling and optional fallback.
    
    Args:
        text: JSON string to parse
        fallback: Default value to return if parsing fails
    
    Returns:
        Parsed JSON object or fallback value
    """
    try:
        return parse_json_with_escaping(text)
    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed: {str(e)}")
        if fallback is not None:
            logging.warning(f"Using fallback value")
            return fallback
        raise
