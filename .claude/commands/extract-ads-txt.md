# Extract ads.txt Command

When the user provides a website URL, extract and display its ads.txt file.

## Instructions

1. **Parse the URL**: Extract the base domain from the user's input
   - Remove any protocol (http://, https://)
   - Remove any path, query parameters, or fragments
   - Remove www. prefix if present
   - Keep only the root domain (e.g., "nytimes.com", "cricbuzz.com")

2. **Construct the ads.txt URL**: Append `/ads.txt` to the domain
   - Format: `https://{domain}/ads.txt`

3. **Fetch the ads.txt file**: Use WebFetch to retrieve the content
   - Request the full raw content of the ads.txt file

4. **Display the results**:
   - If the file exists: Print ALL lines exactly as they appear, preserving:
     - Original formatting
     - Spacing
     - Order of entries
     - Comments (lines starting with #)
     - Empty lines
   - If the file does not exist or returns an error: Print "No ads.txt found."

5. **Do NOT analyze**: Just extract and paste the raw ads.txt content without any interpretation or analysis.

## Examples

- Input: `nytimes.com` -> Fetch `https://nytimes.com/ads.txt`
- Input: `https://www.cricbuzz.com/` -> Fetch `https://cricbuzz.com/ads.txt`
- Input: `www.example.com/page` -> Fetch `https://example.com/ads.txt`

## User Input

$ARGUMENTS
