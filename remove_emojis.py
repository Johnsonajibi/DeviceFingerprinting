#!/usr/bin/env python3
import re
import unicodedata

def remove_emojis(text):
    """Remove all emojis from text using multiple approaches"""
    # Pattern for most emojis
    emoji_pattern = re.compile(
        r'[\U0001F600-\U0001F64F]|'  # emoticons
        r'[\U0001F300-\U0001F5FF]|'  # symbols & pictographs
        r'[\U0001F680-\U0001F6FF]|'  # transport & map symbols
        r'[\U0001F1E0-\U0001F1FF]|'  # flags (iOS)
        r'[\U00002600-\U000026FF]|'  # miscellaneous symbols
        r'[\U00002700-\U000027BF]|'  # dingbats
        r'[\U0001F900-\U0001F9FF]|'  # supplemental symbols and pictographs
        r'[\U0001FA70-\U0001FAFF]'   # symbols and pictographs extended-a
    )
    
    # Remove emoji patterns
    text = emoji_pattern.sub('', text)
    
    # Additional cleanup for any remaining emoji characters
    # This will catch any emoji that might have been missed
    cleaned_lines = []
    for line in text.split('\n'):
        # Remove any character that is categorized as "Symbol, other" and might be an emoji
        cleaned_line = ''.join(char for char in line 
                              if not (unicodedata.category(char).startswith('So') and ord(char) > 0x1F000))
        cleaned_lines.append(cleaned_line)
    
    return '\n'.join(cleaned_lines)

# Read the file
with open('CorrectPQC.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove emojis
cleaned_content = remove_emojis(content)

# Write back to file
with open('CorrectPQC.py', 'w', encoding='utf-8') as f:
    f.write(cleaned_content)

print("All emojis have been removed from the file!")
